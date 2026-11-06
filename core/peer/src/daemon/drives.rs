// SPDX-License-Identifier: AGPL-3.0-or-later
//! **A drive, recorded as a drive on the device** — the record "a drive"
//! resolves against, wherever this device asks which of its person's nodes are
//! drives.
//!
//! The protocol names the thing: *a drive is a tenancy on a vault*, and *a
//! device names a drive by the vault's key and the tenancy, wherever the vault
//! runs*; and *a person may have several drives, on one vault or many*. So the
//! record is the vault's key, the tenancy, and the tree the vault keeps the
//! drive under, with the person's name for it — and, beside them, the paired
//! node the drive is reached through, which is where the dialer finds the
//! vault's addresses and relay. It lives in the `drives` table
//! (`core/device/migrations/0026_drives.sql`, re-keyed by
//! `0028_drives_per_tree.sql`), beside `paired_nodes`, one row per person,
//! vault key, tenancy and tree.
//!
//! **The tenancy, today.** A vault keeps one pool per tenant, and the pool is
//! named by the name the person's device syncs as: every request a device sends
//! a vault names its `user_id`, and the admit checks the vault keeps for this
//! device under that name before it reports success (`refused_as` in
//! `kotton_device::users::pairing`). So a person has one tenancy on a vault,
//! their own name here.
//!
//! **The trees: a place for drives, and the drives in it.** In the pool a
//! vault keeps several drives (`kvaultd::drives`): each drive is a tree made
//! there, `drive-<hex>`, whose name a device sealed and the vault keeps. The
//! tenancy's own tree, `local` ([`TENANCY_TREE`]), is no drive: it is the
//! pool's own mount, and its row here is the vault's — the record that the
//! node is a vault the person keeps drives on ([`record`]), which every made
//! drive's row there hangs from. A tree's name is the vault's word for it,
//! minted fresh for each vault, so it is a key within one person's record on
//! one vault and joins nothing across vaults or persons; the person's name for
//! a drive keys nothing at all. [`list`] — what every reader below that asks
//! *which nodes are drives* reads — is one row per vault the person keeps
//! drives on, [`kept`] is every drive, and [`all`] is every row.
//!
//! **The first drive lives at one vault** (kotton-protocol's *A drive is where things
//! live and a device keeps what its person chose*; kotton #124). The person's
//! first drive, `personal`, is a made drive like any other, whose sealed name
//! carries the one constant id [`FIRST_DRIVE_ID`]. It is made at the first
//! vault the person enrols, by the device that enrols it
//! (`kotton_device::users::drive_verbs::make_first`), lives on that one vault
//! until `drive move` carries it, and is what this device's own tree syncs with
//! ([`first`]); a made drive has no tree on a device yet (drive paths, kotton
//! #58). Every device finds it from the vaults' listings alone, as the
//! finished tree sealed with that id: never by the order its rows were
//! recorded in, a label, or anything a vault says of itself. A vault enrolled
//! after the first holds nothing of the person's until a drive is made or
//! moved there.
//!
//! **Two trees sealed `first`.** A move leaves two for a moment, and two
//! devices apart from each other may each make one; the storage model says the second
//! are not one drive kept twice. Either way this device keeps syncing with the
//! one it synced with before, which its own passes mark ([`mark_synced`]), or
//! with neither until its person chooses, and `status` says so
//! (`kotton_device::users::pins`). A move finishes by retiring its source, so
//! its two become one again at every device's next listing; one cut off
//! before that is finished by running it again on the device that began it,
//! which alone records the two trees its move left ([`MoveBegun`]) and so can
//! tell them from two made apart.
//!
//! **The drive's id, beside the vault's tree** (kotton #171; kotton-protocol
//! #26). A tree id is the vault's and differs at every vault a drive is kept
//! on; the drive's own id ([`Drive::id`]) is minted at random once, at `drive
//! create`, sealed with the name, and shared by every copy a move makes, so it
//! is what tells two finished copies of one drive from two drives of one name
//! (`kotton_device::users::drive_verbs::plan_move`). The first drive's is
//! [`FIRST_DRIVE_ID`] rather than a random one, so every device recognises it.
//! The record keeps it as the device opened it from the sealed name
//! ([`reconcile`], [`Listed`]). It is never sent to a vault, so no vault or
//! relay sees a key it could join two landlords' trees by.
//!
//! **What keys a whole-keeper claim.** A device that keeps a drive whole
//! writes one sealed claim record in that drive, keyed by the device and the
//! drive's id, and nothing else (`kotton_device::users::pins`). The telling
//! — no device keeps a drive whole — and `drive list`'s *which devices keep it
//! whole* read those claims for each drive this record names, by its id, so a
//! drive this record does not name — retired by a move, or never recorded —
//! is counted by nobody and told of to nobody. The record's own drive id is
//! what matches a claim; the person's name for a drive keys nothing.
//!
//! **Who writes a vault's row: [`record`], and nothing else.** It is called
//! from every place a device learns that a node is a vault keeping the
//! person's things, and each of them names a vault; no caller's word makes a
//! node a drive:
//!
//! - **enrolment** — [`super::nodes::finalize_enrolled_node`], for a node
//!   admitted under `Posture::BlindStorage` (`device add` with the blind
//!   posture flag, `drive enrol <invite>`, an invite pasted at Settings' door);
//! - **recovery** — the daemon's `Recover` (`kotton_device::users::recover`),
//!   which takes the line the person's recovery card printed, a vault's
//!   (`OperatedService::Vault`) and saying so, adds that vault as the node to
//!   dial, and records it only once the phrase has proved. Both doors that
//!   recover, `kotton id recover` and the REPL's `id recover`, send that one
//!   request. A `PeerAdd` records no drive: an address and a key say nothing
//!   about what the node keeps, and the flag that once let it say otherwise is
//!   off the wire (#80);
//! - **the membership set** —
//!   [`super::nodes::project_membership_into_allowlist`], for an own-device
//!   member admitted under `Posture::BlindStorage`: what the enrolling device
//!   wrote into the person's sealed set, read on every device it reaches. A
//!   device learns this way of a vault enrolled *after* it joined, in a pass
//!   on a drive it already reaches;
//! - **the join** — `kotton_device::users::pairing::record_handed_drives`, for
//!   each drive the admitting device handed the joiner in the ceremony
//!   (`PairingPayload::FrostShare::drives`). It rests on the issuer's word
//!   inside the SAS-confirmed, identity-attested ceremony, from the device that
//!   holds the identity; a handout the joiner cannot record refuses the join on
//!   both sides — the joiner's refusal is the join's last frame, and the issuer
//!   then records no row for it and introduces it at no drive
//!   (`crate::pairing::JoinAnswer`).
//!   A device that joins after a vault was enrolled learns the drive this way.
//!
//! **Who writes a made drive: [`reconcile`], and nothing else**, from a
//! vault's own listing of the person's drives there, each name opened under
//! the person's key (`kotton_device::users::drive_verbs::follow`): after
//! `drive create` and `drive move`, at `drive list` and `show`, and after every
//! sync pass with the vault. It refines a vault already recorded as a drive,
//! and is refused for any other, so a listing makes no node a drive; and it
//! takes the listing whole, so a drive moved away is forgotten here at this
//! device's next pass — which is how every device follows a drive.
//!
//! Every vault's row arrives at the same place: the vault key is the key of the node row the
//! drive is reached through, the tenancy is the person's name, and the row's
//! posture is `blind-storage`, set in the same transaction as the record on a
//! row that named none. [`record`] never relabels a row: a node paired under
//! another posture (one of the person's own devices, a cosigner) is refused,
//! not made a vault. Enrolment and the projection record only `BlindStorage`
//! members, and `Recover` and the join refuse, before they write anything, a
//! vault whose key is paired under another posture; the join also refuses a
//! handed drive whose DID this device pairs for the person under another key
//! (`check_handed_rows` in `kotton_device::users::pairing`). The join writes
//! the row it records with no posture of its own, so `record` is handed the
//! row as the device held it. No writer of the record relabels a row.
//! What holds them together after that is what may rewrite the row, and a row
//! is the person's and the node's DID's, never a label's ([`super::db`]):
//! re-adding the same key keeps the posture, a different key under the same
//! label is another row and takes neither the posture nor the drive, and
//! removing the row removes the record — each in one transaction. A caller
//! that writes an explicit posture over a drive's row (no caller does) would
//! make them disagree, and the record, not the posture, is what readers
//! believe.
//!
//! **Who reads it.** [`first`] answers *which drive this device's tree syncs
//! with*, for the sync engine's targets and the packs it fetches on demand
//! (`kotton_sync::engine`). [`list`] and [`is_drive`] answer *which nodes are
//! drives* for every other caller — introducing and withdrawing a device at the person's
//! drives (`kotton_device::users::drive_devices`), handing the drives to a
//! device that joins (`kotton_device::users::pairing::drives_to_hand`), handing a vault the doors it
//! holds (`kuserd::agent::vault_doors`), and delivering the phrase-sealed
//! recovery copy (`kuserd`'s `deliver_recovery_copy`). None of them reads a
//! row's posture for it: a row with no posture is a vault added by address or
//! the person's own full device, and nothing in the row tells them apart.
//!
//! **What goes with the node.** The record finds its node by the vault's key
//! among the person's rows ([`list`]); its `node_id` is the label that row is
//! shown under, kept current, and keys nothing. Revoking the node a drive is
//! reached through removes the record with it, in one transaction, unless
//! another row of the person's still carries the key
//! ([`super::db::delete_paired_node`]). [`super::db::insert_paired_node`]
//! writes the row and keeps its drive with it in one transaction: a node row
//! rewritten under another label for the same key keeps its drive and its
//! posture; a different key under a label some row carries is another row,
//! and inherits neither.
//!
//! **What it composes into.** Nothing beyond what the node row already holds:
//! the vault's key is on that row, and the tenancy is the person's own name on
//! their own device. The record is the device's. It is sent once, to one
//! place: to another of the person's own devices as it joins, inside the
//! ceremony's encrypted channel, so that device can reach the vaults — one
//! row for each; the joiner learns the drives in them, `personal` among them,
//! from the vaults at its first pass. It never goes to the vault, which learns nothing from
//! it, nor anywhere else. The vault holds what is its own: the trees, their
//! sizes, and each made drive's name sealed so it cannot read it.

use kotton_schemas::membership::Posture;
use kotton_wire::ipc::{FIRST_DRIVE_ID, TENANCY_TREE};
use kotton_wire::peer::PairedNode;
use sqlx::{Row, SqlitePool};
use std::io;
use std::sync::Arc;

fn db_err(e: sqlx::Error) -> io::Error {
    io::Error::other(e.to_string())
}

/// One of the person's drives, as this device records it.
#[derive(Debug, Clone)]
pub struct Drive {
    /// The vault's key: the key the drive is dialled under.
    pub vault_key: [u8; 32],
    /// The tenancy on that vault: the name the vault keeps the person's pool
    /// under, which is the person's own name on this device today.
    pub tenancy: String,
    /// The tree the vault keeps the drive under, a made drive's
    /// (`kotton_wire::ipc::MadeDrive::tree`); [`TENANCY_TREE`] on the vault's
    /// own row, which is no drive (module doc).
    pub tree: String,
    /// The person's name for it, opened from what the vault keeps sealed;
    /// empty on the vault's own row.
    pub name: String,
    /// The drive's own id (module doc), opened with the name and shared by
    /// every copy a move makes: [`FIRST_DRIVE_ID`] for `personal`. `None` on
    /// the vault's own row, and for a made drive recorded before ids existed
    /// until the next listing of its vault records it.
    pub id: Option<String>,
    /// The paired node the drive is reached through.
    pub node: PairedNode,
}

impl Drive {
    /// Whether this is the vault's own row, the tenancy's own tree: a place
    /// for drives and no drive (module doc).
    pub fn is_tenancy_tree(&self) -> bool {
        self.tree == TENANCY_TREE
    }
}

/// Record that the node `user_id` pairs under `vault_key` is a vault, and the
/// person's tenancy on it a place for their drives: the vault's own row, under
/// the tenancy's own tree, which is no drive. The one writer of a vault's row
/// (module doc).
///
/// Idempotent: recording a drive again re-points it at the node now holding
/// the key and leaves it otherwise as it was. Refused when `user_id` pairs no
/// node under `vault_key`: a drive is reached through a node, and a record
/// with none to reach would be a drive nothing can dial. Refused, with the row
/// left as it is, when that node is paired under a posture other than
/// `blind-storage`: a drive is a tenancy on a vault, and a row that says the
/// node is something else is not relabelled here (module doc).
pub async fn record(db: &Arc<SqlitePool>, user_id: &str, vault_key: &[u8; 32]) -> io::Result<()> {
    let mut tx = kotton_record::immediate::Immediate::begin(db).await?;
    let node: Option<(String, String, Option<String>)> = sqlx::query_as(
        "SELECT id, device_did, posture FROM paired_nodes WHERE user_id = ? AND public_key = ? \
         ORDER BY device_did LIMIT 1",
    )
    .bind(user_id)
    .bind(vault_key.as_slice())
    .fetch_optional(tx.conn())
    .await
    .map_err(db_err)?;
    let Some((node_id, device_did, posture)) = node else {
        return Err(io::Error::other(format!(
            "'{user_id}' pairs no node under the vault key {}, so there is no drive to record",
            hex::encode(vault_key)
        )));
    };
    if let Some(other) = posture.filter(|p| p != Posture::BlindStorage.as_str()) {
        return Err(io::Error::other(format!(
            "'{user_id}' pairs '{node_id}' under the key {} as {other}, not as a vault, so it is not \
             recorded as a drive",
            hex::encode(vault_key)
        )));
    }
    sqlx::query("UPDATE paired_nodes SET posture = ? WHERE user_id = ? AND device_did = ?")
        .bind(Posture::BlindStorage.as_str())
        .bind(user_id)
        .bind(&device_did)
        .execute(tx.conn())
        .await
        .map_err(db_err)?;
    sqlx::query(
        "INSERT INTO drives (user_id, vault_key, tenancy, tree, name, drive_id, node_id, recorded_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?) \
         ON CONFLICT (user_id, vault_key, tenancy, tree) DO UPDATE SET node_id = excluded.node_id",
    )
    .bind(user_id)
    .bind(vault_key.as_slice())
    .bind(tenancy_of(user_id))
    .bind(TENANCY_TREE)
    .bind("")
    .bind(None::<String>)
    .bind(&node_id)
    .bind(kotton_common::time::now_secs())
    .execute(tx.conn())
    .await
    .map_err(db_err)?;
    tx.commit().await
}

/// Take what the vault `vault_key` lists of `user_id`'s drives — each made
/// drive's tree, and the name and id a device of theirs opened for it
/// ([`Listed`]) — as what this
/// device records of the drives made there: every listed tree recorded under
/// its name, and every made drive recorded at that vault and not listed
/// forgotten. The one writer of made drives (module doc). Returns whether the
/// record changed.
///
/// `listed` is the vault's whole listing, never part of one: a tree left out
/// is a tree the vault no longer keeps — retired by a `drive move` from it, on
/// this device or another — and this is how every device follows a drive away
/// from it. The tenancy's own tree is [`record`]'s, the vault's own row, and
/// is neither written nor forgotten here, whatever the listing says of it.
///
/// Refused when `user_id` records no row for the vault `vault_key`: a vault's
/// listing names trees on a vault already one of the person's, and makes no
/// node a drive.
pub async fn reconcile(
    db: &Arc<SqlitePool>,
    user_id: &str,
    vault_key: &[u8; 32],
    listed: &[Listed],
) -> io::Result<bool> {
    let tenancy = tenancy_of(user_id);
    let mut tx = kotton_record::immediate::Immediate::begin(db).await?;
    let first: Option<String> = sqlx::query_scalar(
        "SELECT node_id FROM drives WHERE user_id = ? AND vault_key = ? AND tenancy = ? AND tree = ?",
    )
    .bind(user_id)
    .bind(vault_key.as_slice())
    .bind(tenancy)
    .bind(TENANCY_TREE)
    .fetch_optional(tx.conn())
    .await
    .map_err(db_err)?;
    let Some(node_id) = first else {
        return Err(io::Error::other(format!(
            "'{user_id}' keeps no drive at the vault {}, so what it lists is not recorded",
            hex::encode(vault_key)
        )));
    };
    let recorded: Vec<(String, String, Option<String>)> = sqlx::query_as(
        "SELECT tree, name, drive_id FROM drives WHERE user_id = ? AND vault_key = ? AND tenancy = ? AND tree != ?",
    )
    .bind(user_id)
    .bind(vault_key.as_slice())
    .bind(tenancy)
    .bind(TENANCY_TREE)
    .fetch_all(tx.conn())
    .await
    .map_err(db_err)?;
    let made: Vec<&Listed> = listed.iter().filter(|l| l.tree != TENANCY_TREE).collect();
    let mut changed = false;
    for (tree, _, _) in recorded.iter().filter(|(tree, _, _)| !made.iter().any(|l| l.tree == *tree)) {
        sqlx::query("DELETE FROM drives WHERE user_id = ? AND vault_key = ? AND tenancy = ? AND tree = ?")
            .bind(user_id)
            .bind(vault_key.as_slice())
            .bind(tenancy)
            .bind(tree)
            .execute(tx.conn())
            .await
            .map_err(db_err)?;
        changed = true;
    }
    for Listed { tree, name, id } in made {
        if recorded.iter().any(|(t, n, i)| t == tree && n == name && i.as_deref() == Some(id.as_str())) {
            continue;
        }
        sqlx::query(
            "INSERT INTO drives (user_id, vault_key, tenancy, tree, name, drive_id, node_id, recorded_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?) \
             ON CONFLICT (user_id, vault_key, tenancy, tree) DO UPDATE SET name = excluded.name, \
             drive_id = excluded.drive_id",
        )
        .bind(user_id)
        .bind(vault_key.as_slice())
        .bind(tenancy)
        .bind(tree)
        .bind(name)
        .bind(id)
        .bind(&node_id)
        .bind(kotton_common::time::now_secs())
        .execute(tx.conn())
        .await
        .map_err(db_err)?;
        changed = true;
    }
    tx.commit().await?;
    Ok(changed)
}

/// One made drive as a vault's listing names it, opened on this device: the
/// vault's tree for it, and the person's name and the drive's id from its
/// sealed name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listed {
    pub tree: String,
    pub name: String,
    pub id: String,
}

/// The tenancy a person has on a vault they keep a drive on: their name here,
/// while a vault keeps one pool per tenant (module doc).
fn tenancy_of(user_id: &str) -> &str {
    user_id
}

/// Every row `user_id`'s record holds, each with the node it is reached
/// through, in the order they were recorded: each vault's own row and every
/// drive made there ([`kept`] is the drives alone). The node is the person's
/// row carrying the vault's key, found by that key: the record's `node_id` is
/// the label that row is shown under, and a label keys no row. A record no row
/// of theirs carries the key of is not a drive this device can reach, and is
/// not listed.
pub async fn all(db: &Arc<SqlitePool>, user_id: &str) -> io::Result<Vec<Drive>> {
    read(db, user_id, false).await
}

/// The vaults `user_id` keeps drives on — each vault's own row, one per vault
/// and tenancy — each with the node it is reached through, in the order
/// recorded: what every reader that asks *which nodes are drives* reads
/// (module doc). [`kept`] is the drives in them, and [`first`] the one this
/// device's tree syncs with.
pub async fn list(db: &Arc<SqlitePool>, user_id: &str) -> io::Result<Vec<Drive>> {
    read(db, user_id, true).await
}

/// Every drive `user_id` has, as their vaults list them to this device
/// (module doc): every made drive, `personal` among them, wherever each lives.
pub async fn kept(db: &Arc<SqlitePool>, user_id: &str) -> io::Result<Vec<Drive>> {
    Ok(all(db, user_id).await?.into_iter().filter(|d| !d.is_tenancy_tree()).collect())
}

/// Every finished tree this device records sealed with [`FIRST_DRIVE_ID`]:
/// `personal`, wherever the vaults' listings say it is (module doc). One, or
/// none before any listing names it; two while a move is under way, or when
/// two devices apart from each other each made one. In no order a reader may
/// take as a choice: by the vault's key and the tree, never by when a row was
/// recorded.
pub async fn firsts(db: &Arc<SqlitePool>, user_id: &str) -> io::Result<Vec<Drive>> {
    let mut found: Vec<Drive> = kept(db, user_id).await?.into_iter().filter(|d| d.id.as_deref() == Some(FIRST_DRIVE_ID)).collect();
    found.sort_by(|a, b| (a.vault_key, &a.tree).cmp(&(b.vault_key, &b.tree)));
    Ok(found)
}

/// **The drive this device's own tree syncs with: `personal`, where it
/// lives** (module doc), found in what the vaults listed alone. The one tree
/// sealed [`FIRST_DRIVE_ID`]; of two or more, the one this device's passes
/// last synced with ([`mark_synced`]), or none — this device syncs with
/// neither until its person chooses, and `status` says so. `None` too when no
/// listing this device has read names one: it then syncs with nothing, and
/// never guesses a vault.
pub async fn first(db: &Arc<SqlitePool>, user_id: &str) -> io::Result<Option<Drive>> {
    let found = firsts(db, user_id).await?;
    if found.len() <= 1 {
        return Ok(found.into_iter().next());
    }
    let synced: Vec<(Vec<u8>, String)> = sqlx::query_as(
        "SELECT vault_key, tree FROM drives WHERE user_id = ? AND tenancy = ? AND drive_id = ? AND tree != ? AND synced = 1",
    )
    .bind(user_id)
    .bind(tenancy_of(user_id))
    .bind(FIRST_DRIVE_ID)
    .bind(TENANCY_TREE)
    .fetch_all(db.as_ref())
    .await
    .map_err(db_err)?;
    let before: Vec<Drive> =
        found.into_iter().filter(|d| synced.iter().any(|(k, t)| k.as_slice() == d.vault_key.as_slice() && *t == d.tree)).collect();
    Ok(match <[Drive; 1]>::try_from(before) {
        Ok([one]) => Some(one),
        Err(_) => None,
    })
}

/// Mark the drive at `vault_key` and `tree` as the copy of `personal` this
/// device's tree syncs with, and no other ([`first`]): what a pass that synced
/// with it, and the device that made it, write. A row that is not a copy of
/// `personal` is left unmarked.
pub async fn mark_synced(db: &Arc<SqlitePool>, user_id: &str, vault_key: &[u8; 32], tree: &str) -> io::Result<()> {
    sqlx::query(
        "UPDATE drives SET synced = CASE WHEN vault_key = ? AND tree = ? THEN 1 ELSE 0 END \
         WHERE user_id = ? AND tenancy = ? AND drive_id = ? AND tree != ?",
    )
    .bind(vault_key.as_slice())
    .bind(tree)
    .bind(user_id)
    .bind(tenancy_of(user_id))
    .bind(FIRST_DRIVE_ID)
    .bind(TENANCY_TREE)
    .execute(db.as_ref())
    .await
    .map_err(db_err)?;
    Ok(())
}

/// A tree of a vault's, by the vault's key and the vault's own word for the
/// tree: what [`MoveBegun`] names.
pub type TreeAt = ([u8; 32], String);

/// **The move of `personal` this device began and has not finished**
/// (module doc; migration 0032): the tree it read and the tree it named
/// finished. While both are listed, two trees carry the first drive's id
/// because of this device's own move, not because two devices each made one,
/// so running the move again may retire the first
/// (`kotton_device::users::drive_verbs::move_to`). This device's own, and
/// never sent anywhere.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MoveBegun {
    pub from: TreeAt,
    pub to: TreeAt,
}

impl MoveBegun {
    /// Whether `trees`, every finished tree sealed `first` that the vaults
    /// list, are exactly this move's two.
    pub fn names_exactly(&self, trees: &[TreeAt]) -> bool {
        trees.len() == 2 && trees.contains(&self.from) && trees.contains(&self.to)
    }
}

/// Write the move of `personal` this device began, replacing any earlier one.
pub async fn begin_move(db: &Arc<SqlitePool>, user_id: &str, begun: &MoveBegun) -> io::Result<()> {
    sqlx::query(
        "INSERT OR REPLACE INTO personal_move (user_id, tenancy, from_vault, from_tree, to_vault, to_tree) \
         VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(user_id)
    .bind(tenancy_of(user_id))
    .bind(begun.from.0.as_slice())
    .bind(&begun.from.1)
    .bind(begun.to.0.as_slice())
    .bind(&begun.to.1)
    .execute(db.as_ref())
    .await
    .map_err(db_err)?;
    Ok(())
}

/// The move of `personal` this device began and has not finished, if any.
pub async fn move_begun(db: &Arc<SqlitePool>, user_id: &str) -> io::Result<Option<MoveBegun>> {
    let row: Option<(Vec<u8>, String, Vec<u8>, String)> = sqlx::query_as(
        "SELECT from_vault, from_tree, to_vault, to_tree FROM personal_move WHERE user_id = ? AND tenancy = ?",
    )
    .bind(user_id)
    .bind(tenancy_of(user_id))
    .fetch_optional(db.as_ref())
    .await
    .map_err(db_err)?;
    let Some((from_vault, from_tree, to_vault, to_tree)) = row else { return Ok(None) };
    let key = |k: Vec<u8>| -> io::Result<[u8; 32]> { k.try_into().map_err(|_| io::Error::other("corrupt vault key in personal_move")) };
    Ok(Some(MoveBegun { from: (key(from_vault)?, from_tree), to: (key(to_vault)?, to_tree) }))
}

/// Forget the move of `personal` this device began: it was finished, or it
/// never named a copy finished.
pub async fn end_move(db: &Arc<SqlitePool>, user_id: &str) -> io::Result<()> {
    sqlx::query("DELETE FROM personal_move WHERE user_id = ? AND tenancy = ?")
        .bind(user_id)
        .bind(tenancy_of(user_id))
        .execute(db.as_ref())
        .await
        .map_err(db_err)?;
    Ok(())
}

async fn read(db: &Arc<SqlitePool>, user_id: &str, vaults_only: bool) -> io::Result<Vec<Drive>> {
    let rows = sqlx::query(
        "SELECT vault_key, tenancy, tree, name, drive_id FROM drives WHERE user_id = ? AND (? = 0 OR tree = ?) \
         ORDER BY recorded_at, node_id, tenancy, tree != ?, tree",
    )
    .bind(user_id)
    .bind(vaults_only as i64)
    .bind(TENANCY_TREE)
    .bind(TENANCY_TREE)
    .fetch_all(db.as_ref())
    .await
    .map_err(db_err)?;
    let mut drives = Vec::with_capacity(rows.len());
    for row in rows {
        let vault_key: [u8; 32] = row
            .get::<Vec<u8>, _>("vault_key")
            .try_into()
            .map_err(|_| io::Error::other("corrupt vault_key length in drives"))?;
        let Some(node) = super::db::paired_node_for_key(db, user_id, &vault_key).await? else {
            continue;
        };
        drives.push(Drive {
            vault_key,
            tenancy: row.get("tenancy"),
            tree: row.get("tree"),
            name: row.get("name"),
            id: row.get("drive_id"),
            node,
        });
    }
    Ok(drives)
}

/// The nodes `user_id`'s drives are reached through, one per node.
pub async fn nodes(db: &Arc<SqlitePool>, user_id: &str) -> io::Result<Vec<PairedNode>> {
    let mut nodes: Vec<PairedNode> = Vec::new();
    for drive in list(db, user_id).await? {
        if !nodes.iter().any(|n| n.device_did == drive.node.device_did) {
            nodes.push(drive.node);
        }
    }
    Ok(nodes)
}

/// Whether `node`, a row of `user_id`'s, is one a drive of theirs is reached
/// through: the row a drive's key finds, by its DID, never by the label it
/// shares with some other row.
pub async fn is_drive(db: &Arc<SqlitePool>, user_id: &str, node: &PairedNode) -> io::Result<bool> {
    Ok(list(db, user_id).await?.iter().any(|d| d.node.device_did == node.device_did))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::db as network_db;

    async fn machine_db() -> (tempfile::TempDir, Arc<SqlitePool>) {
        let dir = tempfile::tempdir().unwrap();
        let options = sqlx::sqlite::SqliteConnectOptions::new()
            .filename(dir.path().join("agent.db"))
            .create_if_missing(true);
        let pool = SqlitePool::connect_with(options).await.unwrap();
        sqlx::migrate!("../device/migrations").run(&pool).await.unwrap();
        (dir, Arc::new(pool))
    }

    /// A real Ed25519 public key, so its `did:key` parses.
    fn key(seed: u8) -> [u8; 32] {
        ed25519_dalek::SigningKey::from_bytes(&[seed; 32]).verifying_key().to_bytes()
    }

    fn did(key: &[u8; 32]) -> String {
        kotton_crypto::DidKeyMethod::from_public_key_bytes(key).unwrap().to_string()
    }

    async fn pair(db: &Arc<SqlitePool>, id: &str, key: [u8; 32], posture: Option<&str>) {
        network_db::insert_paired_node(db, id, "alice", &did(&key), &key, "[]", 0, posture).await.unwrap();
    }

    /// **The record is the vault's key and the tenancy, and the node it is
    /// reached through; the row's posture is made to agree.** A node added by
    /// address (no posture) and a full device beside it: only the one recorded
    /// is a drive, and its row now says `blind-storage`.
    #[tokio::test]
    async fn a_recorded_vault_is_a_drive_and_its_row_agrees() {
        let (_dir, db) = machine_db().await;
        pair(&db, "vault", key(9), None).await;
        pair(&db, "laptop", key(6), Some("full")).await;
        assert!(list(&db, "alice").await.unwrap().is_empty(), "nothing is a drive before it is recorded");

        record(&db, "alice", &key(9)).await.unwrap();
        record(&db, "alice", &key(9)).await.unwrap();
        let drives = list(&db, "alice").await.unwrap();
        assert_eq!(drives.len(), 1, "{drives:?}");
        assert_eq!(drives[0].vault_key, key(9));
        assert_eq!(drives[0].tenancy, "alice");
        assert_eq!((drives[0].tree.as_str(), drives[0].name.as_str(), drives[0].id.as_deref()), ("local", "", None), "the vault's row names a drive");
        assert_eq!(drives[0].node.id, "vault");
        assert_eq!(drives[0].node.posture.as_deref(), Some("blind-storage"));
        let row = |id: &'static str| {
            let db = db.clone();
            async move { network_db::paired_node_named(&db, "alice", id).await.unwrap().unwrap() }
        };
        assert!(is_drive(&db, "alice", &row("vault").await).await.unwrap());
        assert!(!is_drive(&db, "alice", &row("laptop").await).await.unwrap());
        assert!(list(&db, "bob").await.unwrap().is_empty(), "alice's drive is nobody else's");
    }

    /// **A node paired under another posture is refused, and its row is left
    /// as it was.** One of the person's own devices (`full`) and a cosigner are
    /// not vaults: recording either as a drive would make it a sync target and
    /// relabel what the row says it is.
    #[tokio::test]
    async fn a_node_paired_as_something_else_is_refused_and_not_relabelled() {
        let (_dir, db) = machine_db().await;
        for (id, seed, posture) in [("laptop", 6, "full"), ("cosigner", 5, "cosigner")] {
            pair(&db, id, key(seed), Some(posture)).await;
            let refused = record(&db, "alice", &key(seed)).await.unwrap_err();
            assert!(refused.to_string().contains("not as a vault"), "{refused}");
            let row = network_db::paired_node_named(&db, "alice", id).await.unwrap().unwrap();
            assert_eq!(row.posture.as_deref(), Some(posture), "the row was relabelled");
        }
        assert!(list(&db, "alice").await.unwrap().is_empty(), "a device was recorded as a drive");
    }

    /// A key no node carries has no drive to record.
    #[tokio::test]
    async fn a_key_no_node_carries_is_refused() {
        let (_dir, db) = machine_db().await;
        let refused = record(&db, "alice", &key(9)).await.unwrap_err();
        assert!(refused.to_string().contains("pairs no node"), "{refused}");
    }

    /// **The record goes with its node.** Revoking the node removes the drive;
    /// the same key re-added under another label keeps it, re-pointed; and a
    /// different key under the vault's label is another row beside it, which
    /// takes neither the drive nor the vault's posture.
    #[tokio::test]
    async fn the_record_follows_the_node_it_is_reached_through() {
        let (_dir, db) = machine_db().await;
        pair(&db, "vault", key(9), None).await;
        record(&db, "alice", &key(9)).await.unwrap();

        pair(&db, "home-vault", key(9), None).await;
        let drives = list(&db, "alice").await.unwrap();
        assert_eq!(drives.iter().map(|d| d.node.id.as_str()).collect::<Vec<_>>(), ["home-vault"]);

        // The same key re-added by address alone keeps its posture; the row
        // and the record still agree.
        pair(&db, "home-vault", key(9), None).await;
        let vault = network_db::paired_node_named(&db, "alice", "home-vault").await.unwrap().unwrap();
        assert_eq!(vault.posture.as_deref(), Some("blind-storage"), "re-adding the vault's key dropped its posture");
        assert!(is_drive(&db, "alice", &vault).await.unwrap());

        // Another key under the vault's label is another node: the vault's row
        // and its drive stay, and the new row takes no posture from them.
        pair(&db, "home-vault", key(4), None).await;
        let drives = list(&db, "alice").await.unwrap();
        assert_eq!(drives.len(), 1, "another key under the label took the drive: {drives:?}");
        assert_eq!(drives[0].node.public_key, key(9));
        let other = network_db::get_paired_node(&db, "alice", &did(&key(4))).await.unwrap().unwrap();
        assert_eq!(other.posture, None, "another key under a vault's label took the vault's posture");
        assert!(!is_drive(&db, "alice", &other).await.unwrap());
        let named = network_db::paired_node_named(&db, "alice", "home-vault").await.unwrap_err();
        let named = named.to_string();
        assert!(named.contains(&did(&key(9))) && named.contains(&did(&key(4))), "the refusal names both DIDs: {named}");

        assert!(network_db::delete_paired_node(&db, "alice", &did(&key(9))).await.unwrap());
        let left: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM drives").fetch_one(db.as_ref()).await.unwrap();
        assert_eq!(left, 0, "revoking the node left its drive recorded");
    }

    /// **Two people's rows under one label are both kept** (kotton #99). A row
    /// is keyed by the person and the node's DID, so alice pairing a node as
    /// `vault` — by `peer add`, at enrolment, or from a handout at a join —
    /// reaches no row of bob's, and bob's drive still names bob's vault.
    #[tokio::test]
    async fn two_peoples_rows_under_one_label_are_both_kept() {
        let (_dir, db) = machine_db().await;
        network_db::insert_paired_node(&db, "vault", "bob", &did(&key(7)), &key(7), "[]", 0, None).await.unwrap();
        record(&db, "bob", &key(7)).await.unwrap();

        pair(&db, "vault", key(9), None).await;
        record(&db, "alice", &key(9)).await.unwrap();

        for (user, k) in [("alice", key(9)), ("bob", key(7))] {
            let rows = network_db::list_paired_nodes(&db, user).await.unwrap();
            assert_eq!(rows.len(), 1, "{user}: {rows:?}");
            assert_eq!((rows[0].id.as_str(), rows[0].public_key), ("vault", k), "{user}'s row was taken");
            let drives = list(&db, user).await.unwrap();
            assert_eq!(drives.len(), 1, "{user}'s drive went: {drives:?}");
            assert_eq!(drives[0].node.public_key, k, "{user}'s drive names a node that is not theirs");
        }

        // One key, two people (two tenants of one vault): each keeps a row,
        // and revoking it for one leaves the other's.
        network_db::insert_paired_node(&db, "household", "bob", &did(&key(9)), &key(9), "[]", 0, None).await.unwrap();
        assert_eq!(network_db::list_paired_nodes(&db, "alice").await.unwrap().len(), 1);
        assert_eq!(network_db::list_paired_nodes(&db, "bob").await.unwrap().len(), 2);
        assert!(network_db::delete_paired_node(&db, "bob", &did(&key(9))).await.unwrap());
        assert_eq!(list(&db, "alice").await.unwrap().len(), 1, "bob's revoke took alice's drive");
    }

    /// **A vault keeps several drives for one person, and the record follows
    /// what the vault lists.** Two drives made at one vault are recorded
    /// beside the vault's own row, each under its own tree and name; `list`
    /// still names the vault once, by that row, and `kept` names the drives
    /// and not it. A listing that leaves one out — a drive moved away —
    /// forgets that one and no other; the vault's row is no listing's to
    /// remove; and a vault the person keeps no drive at records nothing it
    /// lists.
    #[tokio::test]
    async fn the_drives_made_at_a_vault_follow_what_it_lists() {
        let (_dir, db) = machine_db().await;
        pair(&db, "vault", key(9), None).await;
        record(&db, "alice", &key(9)).await.unwrap();
        let made = |tree: &str, name: &str| Listed { tree: tree.into(), name: name.into(), id: format!("id-of-{name}") };

        let changed = reconcile(&db, "alice", &key(9), &[made("local", "ignored"), made("drive-01", "photos"), made("drive-02", "work")])
            .await
            .unwrap();
        assert!(changed);
        let said = |drives: Vec<Drive>| -> Vec<(String, String)> { drives.into_iter().map(|d| (d.tree, d.name)).collect() };
        let made = |tree: &str, name: &str| (tree.to_string(), name.to_string());
        let listed = |tree: &str, name: &str| Listed { tree: tree.into(), name: name.into(), id: format!("id-of-{name}") };
        let ids: Vec<Option<String>> = all(&db, "alice").await.unwrap().into_iter().map(|d| d.id).collect();
        assert_eq!(
            ids,
            [None, Some("id-of-photos".into()), Some("id-of-work".into())],
            "each drive is recorded with its id, and the vault's row with none"
        );
        assert_eq!(
            said(all(&db, "alice").await.unwrap()),
            [made("local", ""), made("drive-01", "photos"), made("drive-02", "work")]
        );
        assert_eq!(said(list(&db, "alice").await.unwrap()), [made("local", "")], "the vault is listed once, by its own row");
        assert_eq!(said(kept(&db, "alice").await.unwrap()), [made("drive-01", "photos"), made("drive-02", "work")], "the vault's row is a drive");
        assert_eq!(nodes(&db, "alice").await.unwrap().len(), 1);
        assert!(!reconcile(&db, "alice", &key(9), &[listed("drive-01", "photos"), listed("drive-02", "work")]).await.unwrap(), "the same listing changed the record");

        // "work" moved away: the vault lists it no longer.
        assert!(reconcile(&db, "alice", &key(9), &[listed("drive-01", "photos")]).await.unwrap());
        assert_eq!(said(all(&db, "alice").await.unwrap()), [made("local", ""), made("drive-01", "photos")]);
        // A listing with nothing in it leaves the vault's row.
        reconcile(&db, "alice", &key(9), &[]).await.unwrap();
        assert_eq!(said(all(&db, "alice").await.unwrap()), [made("local", "")]);

        // A vault that is not one of the person's drives records nothing.
        pair(&db, "elsewhere", key(4), None).await;
        let refused = reconcile(&db, "alice", &key(4), &[listed("drive-03", "x")]).await.unwrap_err();
        assert!(refused.to_string().contains("keeps no drive"), "{refused}");
        assert_eq!(all(&db, "alice").await.unwrap().len(), 1);
        assert!(all(&db, "bob").await.unwrap().is_empty(), "alice's drives are nobody else's");

        // Revoking the vault's node takes every drive kept there.
        reconcile(&db, "alice", &key(9), &[listed("drive-01", "photos")]).await.unwrap();
        assert!(network_db::delete_paired_node(&db, "alice", &did(&key(9))).await.unwrap());
        let left: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM drives").fetch_one(db.as_ref()).await.unwrap();
        assert_eq!(left, 0, "revoking the vault left a drive recorded at it");
    }

    /// `personal` as a vault lists it once a device made it there: a made
    /// tree whose sealed name carries the first drive's id.
    fn personal_at(tree: &str) -> Listed {
        Listed { tree: tree.into(), name: "personal".into(), id: FIRST_DRIVE_ID.into() }
    }

    /// One device's record, as each way of coming to the person writes it:
    /// the vaults' rows, recorded in `order` under `labels`, all in one
    /// second (as a join records the drives it is handed), and then each
    /// vault's listing followed. `home` lists `personal` and `office` lists
    /// nothing, as a vault enrolled after the first does.
    async fn a_device(order: &[usize], labels: [&str; 2], listed: bool) -> (tempfile::TempDir, Arc<SqlitePool>) {
        let (dir, db) = machine_db().await;
        let vaults = [key(9), key(4)];
        for &i in order {
            pair(&db, labels[i], vaults[i], None).await;
            record(&db, "alice", &vaults[i]).await.unwrap();
        }
        sqlx::query("UPDATE drives SET recorded_at = 7").execute(db.as_ref()).await.unwrap();
        if listed {
            for &i in order {
                let listing = if i == 0 { vec![personal_at("drive-0a")] } else { vec![] };
                reconcile(&db, "alice", &vaults[i], &listing).await.unwrap();
            }
        }
        (dir, db)
    }

    /// **Every device finds `personal` from the vaults' listings alone**
    /// (kotton-protocol's storage model; kotton #124, and the previous assessor's probe of #447). A
    /// device that enrolled both vaults, one that joined it and was handed
    /// them in its order, one that joined *that* one and was handed them in
    /// its order, and one that recovered from either vault alone record their
    /// rows in different orders, under different labels, in one second. Each
    /// takes the tree its vaults list sealed `first`, at the vault that lists
    /// it — and before any listing is read, none of them takes any: a device
    /// that has read no listing naming `personal` syncs with nothing, and
    /// never falls back to a vault it recorded first.
    #[tokio::test]
    async fn every_device_finds_personal_from_the_listings_alone() {
        let want = Some((key(9), "drive-0a".to_string()));
        let at = |d: Option<Drive>| d.map(|d| (d.vault_key, d.tree));
        for (who, order, labels) in [
            ("the device that enrolled both", vec![0, 1], ["home", "office"]),
            ("a device that joined it", vec![1, 0], ["zz-home", "aa-office"]),
            ("a device that joined the joiner", vec![0, 1], ["did:key:z6Mk-home", "office"]),
            ("a device that recovered from the vault holding it", vec![0], ["home", "office"]),
            ("a device that recovered from the vault enrolled second", vec![1], ["home", "office"]),
        ] {
            let (_dir, db) = a_device(&order, labels, false).await;
            assert!(first(&db, "alice").await.unwrap().is_none(), "{who} took a drive no listing named");
            let (_dir, db) = a_device(&order, labels, true).await;
            let found = at(first(&db, "alice").await.unwrap());
            if order.contains(&0) {
                assert_eq!(found, want, "{who} took another drive than the one its vaults list as personal");
            } else {
                assert_eq!(found, None, "{who} reaches no vault that lists personal, and took one anyway");
            }
            assert!(kept(&db, "alice").await.unwrap().iter().all(|d| !d.is_tenancy_tree()), "{who} counts a vault's row as a drive");
        }
        let (_dir, db) = a_device(&[0, 1], ["home", "office"], true).await;
        assert!(first(&db, "bob").await.unwrap().is_none(), "alice's personal is bob's");
    }

    /// **Two trees sealed `first`: the one synced with before, or neither**
    /// (kotton-protocol's storage model). A move under way lists `personal` at both vaults: a device
    /// that synced with the copy at home keeps syncing there until the move
    /// retires it, and then follows it to the office. Two devices apart from
    /// each other that each made one leave two with no move between them: a
    /// device that synced with neither — one that recovered, say — takes
    /// neither, whichever it recorded first, and `firsts` names both.
    #[tokio::test]
    async fn of_two_trees_sealed_first_a_device_keeps_the_one_it_synced_with_or_neither() {
        let at = |d: Option<Drive>| d.map(|d| (d.vault_key, d.tree));
        let (_dir, db) = a_device(&[0, 1], ["home", "office"], true).await;
        mark_synced(&db, "alice", &key(9), "drive-0a").await.unwrap();
        // The move names its copy at the office finished.
        reconcile(&db, "alice", &key(4), &[personal_at("drive-0b")]).await.unwrap();
        assert_eq!(firsts(&db, "alice").await.unwrap().len(), 2);
        assert_eq!(at(first(&db, "alice").await.unwrap()), Some((key(9), "drive-0a".into())), "a move under way took the device away from the copy it syncs with");
        // The move retires its source.
        reconcile(&db, "alice", &key(9), &[]).await.unwrap();
        assert_eq!(at(first(&db, "alice").await.unwrap()), Some((key(4), "drive-0b".into())), "the device does not follow the move");

        // Two made apart, and this device synced with neither.
        for order in [vec![0, 1], vec![1, 0]] {
            let (_dir, db) = a_device(&order, ["home", "office"], true).await;
            reconcile(&db, "alice", &key(4), &[personal_at("drive-0b")]).await.unwrap();
            assert!(first(&db, "alice").await.unwrap().is_none(), "a device chose between two drives called personal for its person");
            let both: Vec<[u8; 32]> = firsts(&db, "alice").await.unwrap().into_iter().map(|d| d.vault_key).collect();
            let mut want = vec![key(9), key(4)];
            want.sort();
            assert_eq!(both, want, "firsts is not in the vaults' order");
            mark_synced(&db, "alice", &key(4), "drive-0b").await.unwrap();
            assert_eq!(at(first(&db, "alice").await.unwrap()), Some((key(4), "drive-0b".into())));
        }
    }

    /// **A drive recorded before ids existed is given its id by the next
    /// listing, in place** (kotton #171's migration): migration 0030 leaves a
    /// made drive's id empty; the next listing of
    /// its vault, its sealed name opened, records the id — the same row, the
    /// same name, the same tree.
    #[tokio::test]
    async fn a_drive_recorded_before_ids_is_given_its_id_by_the_next_listing() {
        let (_dir, db) = machine_db().await;
        pair(&db, "vault", key(9), None).await;
        record(&db, "alice", &key(9)).await.unwrap();
        // As #125 recorded a made drive: no id.
        sqlx::query(
            "INSERT INTO drives (user_id, vault_key, tenancy, tree, name, node_id, recorded_at) VALUES ('alice', ?, 'alice', 'drive-01', 'photos', 'vault', 9999999999)",
        )
        .bind(key(9).as_slice())
        .execute(db.as_ref())
        .await
        .unwrap();
        let ids = |drives: Vec<Drive>| -> Vec<(String, Option<String>)> { drives.into_iter().map(|d| (d.tree, d.id)).collect() };
        assert_eq!(ids(all(&db, "alice").await.unwrap()), [("local".into(), None), ("drive-01".into(), None)]);
        let listed = Listed { tree: "drive-01".into(), name: "photos".into(), id: "ab".repeat(16) };
        assert!(reconcile(&db, "alice", &key(9), &[listed]).await.unwrap(), "a listing that gave a drive its id changed nothing");
        assert_eq!(ids(all(&db, "alice").await.unwrap()), [("local".into(), None), ("drive-01".into(), Some("ab".repeat(16)))]);
    }

    /// **The drive record's read-then-write transactions survive another
    /// writer on the same file.** The machine database is shared: the
    /// device's event log commits `events` rows into it from its own task
    /// while a request runs, as a revoke's dial does. A transaction that reads
    /// and then writes must begin as a writer; one that begins deferred takes
    /// a read snapshot, and a commit on another connection before its first
    /// write makes that write fail at once with SQLITE_BUSY ("database is
    /// locked") — the busy timeout does not wait out a stale snapshot. This
    /// pairs, records and revokes a vault over and over against a writer that
    /// never stops, through the pool the daemon opens (WAL, five connections,
    /// a busy timeout), and every call must succeed.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn the_record_is_written_beside_another_writer_on_the_same_file() {
        let dir = tempfile::tempdir().unwrap();
        let pool = kotton_record::open_sqlite(&dir.path().join("agent.db")).await.unwrap();
        sqlx::migrate!("../device/migrations").run(&pool).await.unwrap();
        let db = Arc::new(pool);
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let writer = {
            let (db, stop) = (Arc::clone(&db), Arc::clone(&stop));
            tokio::spawn(async move {
                let mut n = 0u64;
                while !stop.load(std::sync::atomic::Ordering::SeqCst) {
                    n += 1;
                    sqlx::query(
                        "INSERT INTO events (id, category, level, message, timestamp) VALUES (?, 'transport', 'info', 'dial', 0)",
                    )
                    .bind(format!("e{n}"))
                    .execute(db.as_ref())
                    .await
                    .expect("the other writer's insert");
                    tokio::task::yield_now().await;
                }
                n
            })
        };
        for round in 0..150u8 {
            let k = key(round.wrapping_add(10));
            let d = did(&k);
            network_db::insert_paired_node(&db, "vault", "alice", &d, &k, "[]", 0, None)
                .await
                .unwrap_or_else(|e| panic!("round {round}: pairing: {e}"));
            record(&db, "alice", &k).await.unwrap_or_else(|e| panic!("round {round}: recording: {e}"));
            reconcile(&db, "alice", &k, &[Listed { tree: "drive-01".into(), name: "photos".into(), id: "x".into() }])
                .await
                .unwrap_or_else(|e| panic!("round {round}: following: {e}"));
            assert!(
                network_db::delete_paired_node(&db, "alice", &d).await.unwrap_or_else(|e| panic!("round {round}: revoking: {e}")),
                "round {round}: the row was not there to revoke"
            );
        }
        stop.store(true, std::sync::atomic::Ordering::SeqCst);
        assert!(writer.await.unwrap() > 0, "the other writer never wrote");
        let left: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM drives").fetch_one(db.as_ref()).await.unwrap();
        assert_eq!(left, 0);
    }
}
