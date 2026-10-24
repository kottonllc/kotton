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
//! **The trees, and the first drive.** In the pool a vault keeps several
//! drives (`kvaultd::drives`): the tenancy's own tree, `local` — the pool it
//! kept before, the person's *first drive* there, named `personal` on every
//! device because no device sealed it a name — and each drive made beside it,
//! `drive-<hex>`, whose name a device sealed and the vault keeps. A tree's
//! name is the vault's word for it, minted fresh for each vault, so it is a key
//! within one person's record on one vault and joins nothing across vaults or
//! persons; the person's name for a drive keys nothing at all. The first drive
//! is what this device's own tree syncs with, at each vault; a made drive has
//! no tree on a device yet (what a device keeps is pins', kotton #55), so
//! [`list`] — what every reader below that asks *which nodes are drives* reads
//! — is the first drive on each vault, and [`all`] is every drive.
//!
//! **Who writes a first drive: [`record`], and nothing else.** It is called
//! from every place a device learns that a node is a vault keeping the
//! person's things, and each of them names a vault; no caller's word makes a
//! node a drive:
//!
//! - **enrolment** — [`super::nodes::finalize_enrolled_node`], for a node
//!   admitted under `Posture::BlindStorage` (`device add --blind`, `device
//!   admit`, an invite pasted at Settings' door);
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
//!   the joiner only — the issuer has already committed and still lists the
//!   device until `device revoke` (kotton #98).
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
//! All first drives arrive at the same row: the vault key is the key of the node row the
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
//! **Who reads it.** [`list`] and [`is_drive`] answer *which nodes are drives*
//! for every caller — introducing and withdrawing a device at the person's
//! drives (`kotton_device::users::drive_devices`), handing the drives to a
//! device that joins (`kotton_device::users::pairing::drives_to_hand`), the
//! sync engine's targets (`kotton_sync::engine`), handing a vault the doors it
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
//! ceremony's encrypted channel, so that device can reach the drive — the
//! first drive on each vault; the joiner learns the made ones from the vaults
//! at its first pass. It never goes to the vault, which learns nothing from
//! it, nor anywhere else. The vault holds what is its own: the trees, their
//! sizes, and each made drive's name sealed so it cannot read it.

use kotton_schemas::membership::Posture;
use kotton_wire::ipc::{FIRST_DRIVE_NAME, FIRST_DRIVE_TREE};
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
    /// The tree the vault keeps the drive under: [`FIRST_DRIVE_TREE`] for the
    /// tenancy's own, or a made drive's (`kotton_wire::ipc::MadeDrive::tree`).
    pub tree: String,
    /// The person's name for it: [`FIRST_DRIVE_NAME`] for the tenancy's own
    /// tree, the name opened from what the vault keeps sealed otherwise.
    pub name: String,
    /// The paired node the drive is reached through.
    pub node: PairedNode,
}

impl Drive {
    /// Whether this is the tenancy's own tree on its vault — the drive this
    /// device's own tree syncs with (module doc).
    pub fn is_first(&self) -> bool {
        self.tree == FIRST_DRIVE_TREE
    }
}

/// Record that the node `user_id` pairs under `vault_key` is a vault, and the
/// person's tenancy on it a drive — the tenancy's own tree, their first drive
/// there. The one writer of a vault's first drive (module doc).
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
        "INSERT INTO drives (user_id, vault_key, tenancy, tree, name, node_id, recorded_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?) \
         ON CONFLICT (user_id, vault_key, tenancy, tree) DO UPDATE SET node_id = excluded.node_id",
    )
    .bind(user_id)
    .bind(vault_key.as_slice())
    .bind(tenancy_of(user_id))
    .bind(FIRST_DRIVE_TREE)
    .bind(FIRST_DRIVE_NAME)
    .bind(&node_id)
    .bind(kotton_common::time::now_secs())
    .execute(tx.conn())
    .await
    .map_err(db_err)?;
    tx.commit().await
}

/// Take what the vault `vault_key` lists of `user_id`'s drives — each made
/// drive's tree and the name a device of theirs opened for it — as what this
/// device records of the drives made there: every listed tree recorded under
/// its name, and every made drive recorded at that vault and not listed
/// forgotten. The one writer of made drives (module doc). Returns whether the
/// record changed.
///
/// `listed` is the vault's whole listing, never part of one: a tree left out
/// is a tree the vault no longer keeps — retired by a `drive move` from it, on
/// this device or another — and this is how every device follows a drive away
/// from it. The tenancy's own tree is [`record`]'s, and is neither written nor
/// forgotten here, whatever the listing says of it.
///
/// Refused when `user_id` records no first drive at `vault_key`: a vault's
/// listing names trees on a vault already one of the person's, and makes no
/// node a drive.
pub async fn reconcile(
    db: &Arc<SqlitePool>,
    user_id: &str,
    vault_key: &[u8; 32],
    listed: &[(String, String)],
) -> io::Result<bool> {
    let tenancy = tenancy_of(user_id);
    let mut tx = kotton_record::immediate::Immediate::begin(db).await?;
    let first: Option<String> = sqlx::query_scalar(
        "SELECT node_id FROM drives WHERE user_id = ? AND vault_key = ? AND tenancy = ? AND tree = ?",
    )
    .bind(user_id)
    .bind(vault_key.as_slice())
    .bind(tenancy)
    .bind(FIRST_DRIVE_TREE)
    .fetch_optional(tx.conn())
    .await
    .map_err(db_err)?;
    let Some(node_id) = first else {
        return Err(io::Error::other(format!(
            "'{user_id}' keeps no drive at the vault {}, so what it lists is not recorded",
            hex::encode(vault_key)
        )));
    };
    let recorded: Vec<(String, String)> = sqlx::query_as(
        "SELECT tree, name FROM drives WHERE user_id = ? AND vault_key = ? AND tenancy = ? AND tree != ?",
    )
    .bind(user_id)
    .bind(vault_key.as_slice())
    .bind(tenancy)
    .bind(FIRST_DRIVE_TREE)
    .fetch_all(tx.conn())
    .await
    .map_err(db_err)?;
    let made: Vec<&(String, String)> = listed.iter().filter(|(tree, _)| tree != FIRST_DRIVE_TREE).collect();
    let mut changed = false;
    for (tree, _) in recorded.iter().filter(|(tree, _)| !made.iter().any(|(t, _)| t == tree)) {
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
    for (tree, name) in made {
        if recorded.iter().any(|(t, n)| t == tree && n == name) {
            continue;
        }
        sqlx::query(
            "INSERT INTO drives (user_id, vault_key, tenancy, tree, name, node_id, recorded_at) \
             VALUES (?, ?, ?, ?, ?, ?, ?) \
             ON CONFLICT (user_id, vault_key, tenancy, tree) DO UPDATE SET name = excluded.name",
        )
        .bind(user_id)
        .bind(vault_key.as_slice())
        .bind(tenancy)
        .bind(tree)
        .bind(name)
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

/// The tenancy a person has on a vault they keep a drive on: their name here,
/// while a vault keeps one pool per tenant (module doc).
fn tenancy_of(user_id: &str) -> &str {
    user_id
}

/// Every drive `user_id` has, each with the node it is reached through, in the
/// order they were recorded — the first drive on each vault and every drive
/// made beside it. The node is the person's row carrying the vault's key,
/// found by that key: the record's `node_id` is the label that row is shown
/// under, and a label keys no row. A record no row of theirs carries the key
/// of is not a drive this device can reach, and is not listed.
pub async fn all(db: &Arc<SqlitePool>, user_id: &str) -> io::Result<Vec<Drive>> {
    read(db, user_id, false).await
}

/// The first drive on each vault `user_id` keeps drives on — the tenancy's
/// own tree, one per vault and tenancy, the drive this device's own tree syncs
/// with — each with the node it is reached through, in the order recorded.
/// What every reader that asks *which nodes are drives* reads (module doc);
/// [`all`] is every drive.
pub async fn list(db: &Arc<SqlitePool>, user_id: &str) -> io::Result<Vec<Drive>> {
    read(db, user_id, true).await
}

async fn read(db: &Arc<SqlitePool>, user_id: &str, first_only: bool) -> io::Result<Vec<Drive>> {
    let rows = sqlx::query(
        "SELECT vault_key, tenancy, tree, name FROM drives WHERE user_id = ? AND (? = 0 OR tree = ?) \
         ORDER BY recorded_at, node_id, tenancy, tree != ?, tree",
    )
    .bind(user_id)
    .bind(first_only as i64)
    .bind(FIRST_DRIVE_TREE)
    .bind(FIRST_DRIVE_TREE)
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
        assert_eq!((drives[0].tree.as_str(), drives[0].name.as_str()), ("local", "personal"), "the first drive is the tenancy's own tree");
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
    /// beside its first, each under its own tree and name; `list` still names
    /// the vault once, by its first drive. A listing that leaves one out — a
    /// drive moved away — forgets that one and no other; the first drive is
    /// the vault's own and no listing removes it; and a vault the person keeps
    /// no drive at records nothing it lists.
    #[tokio::test]
    async fn the_drives_made_at_a_vault_follow_what_it_lists() {
        let (_dir, db) = machine_db().await;
        pair(&db, "vault", key(9), None).await;
        record(&db, "alice", &key(9)).await.unwrap();
        let made = |tree: &str, name: &str| (tree.to_string(), name.to_string());

        let changed = reconcile(&db, "alice", &key(9), &[made("local", "ignored"), made("drive-01", "photos"), made("drive-02", "work")])
            .await
            .unwrap();
        assert!(changed);
        let said = |drives: Vec<Drive>| -> Vec<(String, String)> { drives.into_iter().map(|d| (d.tree, d.name)).collect() };
        assert_eq!(
            said(all(&db, "alice").await.unwrap()),
            [made("local", "personal"), made("drive-01", "photos"), made("drive-02", "work")]
        );
        assert_eq!(said(list(&db, "alice").await.unwrap()), [made("local", "personal")], "the vault is listed once, by its first drive");
        assert_eq!(nodes(&db, "alice").await.unwrap().len(), 1);
        assert!(!reconcile(&db, "alice", &key(9), &[made("drive-01", "photos"), made("drive-02", "work")]).await.unwrap(), "the same listing changed the record");

        // "work" moved away: the vault lists it no longer.
        assert!(reconcile(&db, "alice", &key(9), &[made("drive-01", "photos")]).await.unwrap());
        assert_eq!(said(all(&db, "alice").await.unwrap()), [made("local", "personal"), made("drive-01", "photos")]);
        // A listing with nothing in it leaves the first drive.
        reconcile(&db, "alice", &key(9), &[]).await.unwrap();
        assert_eq!(said(all(&db, "alice").await.unwrap()), [made("local", "personal")]);

        // A vault that is not one of the person's drives records nothing.
        pair(&db, "elsewhere", key(4), None).await;
        let refused = reconcile(&db, "alice", &key(4), &[made("drive-03", "x")]).await.unwrap_err();
        assert!(refused.to_string().contains("keeps no drive"), "{refused}");
        assert_eq!(all(&db, "alice").await.unwrap().len(), 1);
        assert!(all(&db, "bob").await.unwrap().is_empty(), "alice's drives are nobody else's");

        // Revoking the vault's node takes every drive kept there.
        reconcile(&db, "alice", &key(9), &[made("drive-01", "photos")]).await.unwrap();
        assert!(network_db::delete_paired_node(&db, "alice", &did(&key(9))).await.unwrap());
        let left: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM drives").fetch_one(db.as_ref()).await.unwrap();
        assert_eq!(left, 0, "revoking the vault left a drive recorded at it");
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
            reconcile(&db, "alice", &k, &[("drive-01".into(), "photos".into())])
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
