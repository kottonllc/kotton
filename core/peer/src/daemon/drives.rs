// SPDX-License-Identifier: AGPL-3.0-or-later
//! **A drive, recorded as a drive on the device** — the record "a drive"
//! resolves against, wherever this device asks which of its person's nodes are
//! drives.
//!
//! The protocol names the thing: *a drive is a tenancy on a vault*, and *a
//! device names a drive by the vault's key and the tenancy, wherever the vault
//! runs*. So the record is those two — the vault's key and
//! the tenancy — and, beside them, the paired node the drive is reached
//! through, which is where the dialer finds the vault's addresses and relay.
//! It lives in the `drives` table (`core/device/migrations/0026_drives.sql`),
//! beside `paired_nodes`, one row per person, vault key and tenancy.
//!
//! **The tenancy, today.** A vault keeps one pool per tenant, and the pool is
//! named by the name the person's device syncs as: every request a device sends
//! a vault names its `user_id`, and the admit checks the vault keeps for this
//! device under that name before it reports success (`refused_as` in
//! `kotton_device::users::pairing`). So a person has one tenancy on a vault,
//! their own name here, and the record names that one. The key already admits
//! several, for when a vault keeps more than one drive for a person.
//!
//! **Who writes it: [`record`], and nothing else.** It is called from every
//! place a device learns that a node is a vault keeping the person's things,
//! and each of them names a vault; no caller's word makes a node a drive:
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
//! All arrive at the same row: the vault key is the key of the node row the
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
//! ceremony's encrypted channel, so that device can reach the drive. It
//! never goes to the vault, which learns nothing from it, nor anywhere else.

use kotton_schemas::membership::Posture;
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
    /// The paired node the drive is reached through.
    pub node: PairedNode,
}

/// Record that the node `user_id` pairs under `vault_key` is a vault, and the
/// person's tenancy on it a drive. The one writer of the record (module doc).
///
/// Idempotent: recording a drive again re-points it at the node now holding
/// the key and leaves it otherwise as it was. Refused when `user_id` pairs no
/// node under `vault_key`: a drive is reached through a node, and a record
/// with none to reach would be a drive nothing can dial. Refused, with the row
/// left as it is, when that node is paired under a posture other than
/// `blind-storage`: a drive is a tenancy on a vault, and a row that says the
/// node is something else is not relabelled here (module doc).
pub async fn record(db: &Arc<SqlitePool>, user_id: &str, vault_key: &[u8; 32]) -> io::Result<()> {
    let mut tx = db.begin().await.map_err(db_err)?;
    let node: Option<(String, String, Option<String>)> = sqlx::query_as(
        "SELECT id, device_did, posture FROM paired_nodes WHERE user_id = ? AND public_key = ? \
         ORDER BY device_did LIMIT 1",
    )
    .bind(user_id)
    .bind(vault_key.as_slice())
    .fetch_optional(&mut *tx)
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
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;
    sqlx::query(
        "INSERT INTO drives (user_id, vault_key, tenancy, node_id, recorded_at) VALUES (?, ?, ?, ?, ?) \
         ON CONFLICT (user_id, vault_key, tenancy) DO UPDATE SET node_id = excluded.node_id",
    )
    .bind(user_id)
    .bind(vault_key.as_slice())
    .bind(tenancy_of(user_id))
    .bind(&node_id)
    .bind(kotton_common::time::now_secs())
    .execute(&mut *tx)
    .await
    .map_err(db_err)?;
    tx.commit().await.map_err(db_err)
}

/// The tenancy a person has on a vault they keep a drive on: their name here,
/// while a vault keeps one pool per tenant (module doc).
fn tenancy_of(user_id: &str) -> &str {
    user_id
}

/// Every drive `user_id` has, each with the node it is reached through, in the
/// order they were recorded. The node is the person's row carrying the vault's
/// key, found by that key: the record's `node_id` is the label that row is
/// shown under, and a label keys no row. A record no row of theirs carries the
/// key of is not a drive this device can reach, and is not listed.
pub async fn list(db: &Arc<SqlitePool>, user_id: &str) -> io::Result<Vec<Drive>> {
    let rows = sqlx::query(
        "SELECT vault_key, tenancy FROM drives WHERE user_id = ? ORDER BY recorded_at, node_id, tenancy",
    )
    .bind(user_id)
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
        drives.push(Drive { vault_key, tenancy: row.get("tenancy"), node });
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
        assert!(named.to_string().contains("name the one you mean by its DID"), "{named}");

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
}
