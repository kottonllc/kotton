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
//! place a device learns that a node is a vault keeping the person's things:
//!
//! - **enrolment** — [`super::nodes::finalize_enrolled_node`], for a node
//!   admitted under `Posture::BlindStorage` (`device add --blind`, `device
//!   admit`, an invite pasted at Settings' door);
//! - **`recover`** — the CLI's `kotton id recover` adds the vault the person's
//!   line names with `PeerAdd { drive: true }` ([`super::nodes::peer_add`]),
//!   because the line it was given is a vault's (`OperatedService::Vault`) and
//!   says so. A plain `PeerAdd` records no drive: an address and a key say
//!   nothing about what the node keeps;
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
//! posture is set to `blind-storage` in the same transaction as the record.
//! What holds them together after that is what may rewrite the row:
//! re-adding the same key keeps the posture, a different key under the label
//! takes neither the posture nor the drive, and removing the row removes the
//! record — each in one transaction ([`super::db`]). A caller that writes an
//! explicit posture over a drive's row (no caller does) would make them
//! disagree, and the record, not the posture, is what readers believe.
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
//! **What goes with the node.** Revoking the node a drive is reached through
//! removes the record with it, in one transaction
//! ([`super::db::delete_paired_node`]). [`super::db::insert_paired_node`]
//! writes the row and re-points or drops its drive in one transaction: a node
//! row rewritten under another label for the same key keeps its drive and its
//! posture; a label taken by a different key inherits neither the drive nor
//! the old row's posture.
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
/// with none to reach would be a drive nothing can dial.
pub async fn record(db: &Arc<SqlitePool>, user_id: &str, vault_key: &[u8; 32]) -> io::Result<()> {
    let mut tx = db.begin().await.map_err(db_err)?;
    let node: Option<String> = sqlx::query_scalar("SELECT id FROM paired_nodes WHERE user_id = ? AND public_key = ? LIMIT 1")
        .bind(user_id)
        .bind(vault_key.as_slice())
        .fetch_optional(&mut *tx)
        .await
        .map_err(db_err)?;
    let Some(node_id) = node else {
        return Err(io::Error::other(format!(
            "'{user_id}' pairs no node under the vault key {}, so there is no drive to record",
            hex::encode(vault_key)
        )));
    };
    sqlx::query("UPDATE paired_nodes SET posture = ? WHERE user_id = ? AND id = ?")
        .bind(Posture::BlindStorage.as_str())
        .bind(user_id)
        .bind(&node_id)
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
/// order they were recorded. A record whose node no longer carries the vault's
/// key is not a drive this device can reach, and is not listed.
pub async fn list(db: &Arc<SqlitePool>, user_id: &str) -> io::Result<Vec<Drive>> {
    let rows = sqlx::query(
        "SELECT vault_key, tenancy, node_id FROM drives WHERE user_id = ? ORDER BY recorded_at, node_id, tenancy",
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
        let node_id: String = row.get("node_id");
        let Some(node) = super::db::get_paired_node_by_id(db, user_id, &node_id).await? else {
            continue;
        };
        if node.public_key != vault_key {
            continue;
        }
        drives.push(Drive { vault_key, tenancy: row.get("tenancy"), node });
    }
    Ok(drives)
}

/// The nodes `user_id`'s drives are reached through, one per node.
pub async fn nodes(db: &Arc<SqlitePool>, user_id: &str) -> io::Result<Vec<PairedNode>> {
    let mut nodes: Vec<PairedNode> = Vec::new();
    for drive in list(db, user_id).await? {
        if !nodes.iter().any(|n| n.id == drive.node.id) {
            nodes.push(drive.node);
        }
    }
    Ok(nodes)
}

/// Whether the node `user_id` pairs as `node_id` is one a drive of theirs is
/// reached through.
pub async fn is_drive(db: &Arc<SqlitePool>, user_id: &str, node_id: &str) -> io::Result<bool> {
    Ok(list(db, user_id).await?.iter().any(|d| d.node.id == node_id))
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
        assert!(is_drive(&db, "alice", "vault").await.unwrap());
        assert!(!is_drive(&db, "alice", "laptop").await.unwrap());
        assert!(list(&db, "bob").await.unwrap().is_empty(), "alice's drive is nobody else's");
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
    /// different key under the vault's old label is not the drive.
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
        let row = network_db::get_paired_node_by_id(&db, "alice", "home-vault").await.unwrap().unwrap();
        assert_eq!(row.posture.as_deref(), Some("blind-storage"), "re-adding the vault's key dropped its posture");
        assert!(is_drive(&db, "alice", "home-vault").await.unwrap());

        // Another key under the vault's label is not the vault: no drive, and
        // no posture taken from the row it replaced.
        pair(&db, "home-vault", key(4), None).await;
        assert!(list(&db, "alice").await.unwrap().is_empty(), "another key under the label is not the drive");
        let row = network_db::get_paired_node_by_id(&db, "alice", "home-vault").await.unwrap().unwrap();
        assert_eq!(row.public_key, key(4));
        assert_eq!(row.posture, None, "another key under a vault's label took the vault's posture");
        let left: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM drives").fetch_one(db.as_ref()).await.unwrap();
        assert_eq!(left, 0, "a drive record outlived the key it named under that label");

        pair(&db, "vault", key(9), None).await;
        record(&db, "alice", &key(9)).await.unwrap();
        assert!(network_db::delete_paired_node(&db, "alice", "vault").await.unwrap());
        let left: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM drives").fetch_one(db.as_ref()).await.unwrap();
        assert_eq!(left, 0, "revoking the node left its drive recorded");
    }
}
