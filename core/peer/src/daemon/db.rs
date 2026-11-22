// SPDX-License-Identifier: AGPL-3.0-or-later
//! DB access for network/pairing tables.
//!
//! Tables: `paired_nodes`, `ephemeral_sessions`, `mount_configs`,
//! created by `migrations/0002_v0_3_network.sql`; and `operator_key`, by
//! `migrations/0024_operator_key.sql`. The `drives` table beside `paired_nodes`
//! is [`super::drives`]'s, which says what a drive record is; the two functions
//! here that write or remove a node row keep its drive with it. A device's
//! sync rules, which name drives, are [`super::drive_rules`]'s.
//!
//! **A `paired_nodes` row is one person's, and is named by its key.** The
//! table is keyed by that person and the node's DID
//! (`migrations/0027_paired_nodes_per_person.sql`), and the DID is the row's
//! name and nothing else: the store's key for the row, and a name a person
//! types (kottonllc/kotton#597, 29A). The one writer, [`insert_paired_node`],
//! takes the key and makes the name: the DID the person's row for that key is
//! stored under, or the key's derivation, its `did:key`, for a new row (27A,
//! 30A). So a row this build writes has a DID that is a function of its key,
//! and a person has one row per key. A row an earlier build stored under
//! another string, or a second row for a key, stands by its bytes (5B): it is
//! rewritten under the name it has, and is removed by `device revoke`, never
//! renamed. The vault's admit keeps its own statement (`kvaultd::devices`) and
//! holds the same rule. Its `id` is the
//! label the person sees it under and keys nothing: a label may come from
//! elsewhere (the name a device announced at a join, a drive's label handed at
//! one), so a write under it reaches no other row, and two of one person's
//! rows may carry it. What names a row is [`get_paired_node`]; a verb a person
//! names a node in resolves the name through the one resolver,
//! `super::nodes::node_named`, whose rows are [`paired_node_named`]'s, which
//! refuses a label two rows carry rather than pick one.
//!
//! **A transaction here that reads and then writes begins as the writer**
//! (`kotton_record::immediate::Immediate`), here and in [`super::drives`]. The
//! machine database is shared: the device's event log commits into it from
//! its own task while a request runs, and a deferred transaction whose read
//! snapshot such a commit overtakes fails its first write at once with
//! "database is locked", which no busy timeout waits out. That is how a
//! revoke failed on Windows, where the event log's commit landed between
//! `delete_paired_node`'s read and its delete.

use kotton_wire::did::{Did, DidError};
use kotton_wire::peer::{EphemeralSession, MountConfig, PairedNode};
use kotton_wire::GrantEnvelope;
use kotton_crypto::ed25519::VerifyingKey;
use kotton_schemas::membership::Posture;
use sqlx::{Row, SqlitePool};
use std::collections::HashSet;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

fn db_err(e: sqlx::Error) -> io::Error {
    io::Error::other(e.to_string())
}

fn json_err(e: serde_json::Error) -> io::Error {
    io::Error::other(e.to_string())
}

fn did_err(e: DidError) -> io::Error {
    io::Error::other(e.to_string())
}

// ---------------------------------------------------------------------------
// paired_nodes
// ---------------------------------------------------------------------------

/// **The one order among a person's rows that hold one key**
/// (kottonllc/kotton#622): the most recently paired first, then by DID as
/// stored, compared as bytes (as SQLite compares the column). It is the order
/// [`list_paired_nodes`] lists in, so the row a write reaches for a key is the
/// row listed first for it (kottonllc/kotton#597, 65A): a write sets
/// `paired_at`, and the row it rewrote is first afterwards. Two rows of one
/// person's never share a DID (the table's key), so no two rows tie.
pub fn listed_before(a: &PairedNode, b: &PairedNode) -> std::cmp::Ordering {
    b.paired_at
        .cmp(&a.paired_at)
        .then_with(|| a.device_did.to_string().cmp(&b.device_did.to_string()))
}

/// **The row of `rows`, one person's, that `key` is reached through**: the first
/// of those that hold it by [`listed_before`], in whatever order `rows` come.
/// `None` when none holds it.
///
/// The one function for that row (kottonllc/kotton#622). Every reader that
/// takes one row for a key goes through it: the writer and the re-address
/// ([`insert_paired_node`], [`add_paired_node_if_absent`],
/// [`readdress_paired_node_for_key`]), [`paired_node_for_key`] and so the drive
/// record's node ([`super::drives`]), a recovery's row for its line
/// (`kotton_device::users::recover`), and co-signer selection
/// (`super::nodes`). So the row a write reaches, the row a drive is reached
/// through and the row dialled are one row. Where two rows hold a key, which
/// only an earlier build can have stored, the other is left as it is (5B), and
/// the first is chosen whether or not it has an address.
pub fn reached_through<'a>(rows: impl IntoIterator<Item = &'a PairedNode>, key: &[u8; 32]) -> Option<&'a PairedNode> {
    rows.into_iter().filter(|r| r.public_key == *key).min_by(|a, b| listed_before(a, b))
}

/// [`reached_through`] over `user_id`'s rows that hold `public_key`, read inside
/// the caller's transaction or on its connection.
pub(crate) async fn row_for_key(
    conn: &mut sqlx::SqliteConnection,
    user_id: &str,
    public_key: &[u8; 32],
) -> io::Result<Option<PairedNode>> {
    let rows = sqlx::query(&format!(
        "SELECT {NODE_COLUMNS} FROM paired_nodes WHERE user_id = ? AND public_key = ?"
    ))
    .bind(user_id)
    .bind(public_key.as_slice())
    .fetch_all(conn)
    .await
    .map_err(db_err)?;
    let rows = rows.iter().map(node_of).collect::<io::Result<Vec<_>>>()?;
    Ok(reached_through(&rows, public_key).cloned())
}

/// Write `user_id`'s row for `key`, labelled `id`, at `addresses_json`, as of
/// `now`, and return it as it then stands.
///
/// **A row is named by its key, and the writer makes the name.** It takes the
/// rule's key and no DID (kottonllc/kotton#597, 27A), so no caller hands the
/// store a second name for a key:
///
/// - **A key the person has a row for** rewrites that row in place, under its
///   DID as stored, whatever string an earlier build stored there (5B, 30A):
///   the label and address this write brings, and the posture where it brings
///   one; a posture it does not bring, and the relay the row was last known
///   at, are kept. Where two of their rows hold the key, the one
///   [`list_paired_nodes`] lists first is rewritten and the other is left as
///   it is (65A). No second row is written for a key.
/// - **Otherwise** the row is written under the derivation's string,
///   [`kotton_crypto::DidKeyMethod::from_public_key`].
/// - **Where that string is already a row's DID beside another key**, which
///   only an earlier build can have stored, the write is refused, names that
///   row, and writes nothing (30A).
///
/// A write that follows this one names the row by the DID returned (the relay a
/// ceremony learned, [`update_paired_node_relay`]). A drive under the key shows
/// the row's label ([`super::drives`]), written in the same transaction.
// Seven arguments: the row's columns that a writer brings.
#[allow(clippy::too_many_arguments)]
pub async fn insert_paired_node(
    db: &Arc<SqlitePool>,
    id: &str,
    user_id: &str,
    key: &VerifyingKey,
    addresses_json: &str,
    now: i64,
    posture: Option<&str>,
) -> io::Result<PairedNode> {
    // One transaction: the row, and the drive it may be reached for
    // (`super::drives`), are written together or not at all, so no reader sees
    // a row that says one thing and a record that says another.
    let mut tx = kotton_record::immediate::Immediate::begin(db).await?;
    let node = write_row(tx.conn(), id, user_id, key, addresses_json, now, posture).await?;
    tx.commit().await?;
    Ok(node)
}

/// [`insert_paired_node`] where no row of `user_id`'s holds `key`; `Ok(None)`,
/// with nothing written and nothing changed, where one does.
///
/// For a writer that brings nothing a row may lack: a device admitted on proof,
/// whose label is made and which knows no address, and the membership
/// projection, which writes a cache row "without clobbering learned addresses"
/// (kottonllc/kotton#597, 69A).
///
/// **It reads first, and begins as the writer only where it may write.** The
/// projection asks this of every own-device member on every pass, and in the
/// common case a row already holds the key: that is a plain read, which takes
/// no writer's lock on the shared machine database. Where no row held the key,
/// the read is made again inside the immediate transaction that writes, so a
/// row written between the two is found and nothing is added beside it.
#[allow(clippy::too_many_arguments)]
pub async fn add_paired_node_if_absent(
    db: &Arc<SqlitePool>,
    id: &str,
    user_id: &str,
    key: &VerifyingKey,
    addresses_json: &str,
    now: i64,
    posture: Option<&str>,
) -> io::Result<Option<PairedNode>> {
    add_paired_node_if_absent_after(db, id, user_id, key, addresses_json, now, posture, async {}).await
}

/// [`add_paired_node_if_absent`], with `between` awaited after the plain read
/// finds no row and before the transaction begins: a test writes a row there,
/// to hold that the read inside the transaction finds it.
#[allow(clippy::too_many_arguments)]
async fn add_paired_node_if_absent_after(
    db: &Arc<SqlitePool>,
    id: &str,
    user_id: &str,
    key: &VerifyingKey,
    addresses_json: &str,
    now: i64,
    posture: Option<&str>,
    between: impl std::future::Future<Output = ()>,
) -> io::Result<Option<PairedNode>> {
    {
        let mut conn = db.acquire().await.map_err(db_err)?;
        if row_for_key(&mut conn, user_id, key.as_bytes()).await?.is_some() {
            return Ok(None);
        }
    }
    between.await;
    let mut tx = kotton_record::immediate::Immediate::begin(db).await?;
    if row_for_key(tx.conn(), user_id, key.as_bytes()).await?.is_some() {
        // Dropped unended: the transaction rolls back, and it wrote nothing.
        return Ok(None);
    }
    let node = write_row(tx.conn(), id, user_id, key, addresses_json, now, posture).await?;
    tx.commit().await?;
    Ok(Some(node))
}

#[cfg(test)]
mod add_only {
    use super::*;

    async fn agent_db(dir: &tempfile::TempDir) -> Arc<SqlitePool> {
        let options = sqlx::sqlite::SqliteConnectOptions::new()
            .filename(dir.path().join("agent.db"))
            .create_if_missing(true);
        let pool = SqlitePool::connect_with(options).await.unwrap();
        sqlx::migrate!("../device/migrations").run(&pool).await.unwrap();
        Arc::new(pool)
    }

    /// **A row written after the plain read and before the transaction is found
    /// inside the transaction**, and the add-only form writes nothing beside it:
    /// one row for the key, the one written between, as it was written.
    #[tokio::test]
    async fn a_row_written_between_the_two_reads_is_found_and_nothing_is_added() {
        let dir = tempfile::tempdir().unwrap();
        let db = agent_db(&dir).await;
        let key = kotton_crypto::ed25519::verifying_key(&ed25519_dalek::SigningKey::from_bytes(&[64; 32]));
        let spelled = kotton_crypto::DidKeyMethod::spelled_otherwise(key.as_bytes()).to_string();
        let between = {
            let (db, spelled) = (Arc::clone(&db), spelled.clone());
            async move {
                seed_paired_node_as_stored(&db, "laptop", "alice", &spelled, key.as_bytes(), "[]", 5, Some("full")).await.unwrap();
            }
        };
        let added = add_paired_node_if_absent_after(&db, "recovered", "alice", &key, "[]", 10, None, between).await.unwrap();
        assert!(added.is_none(), "a row was added beside the one written between: {added:?}");
        let rows = list_paired_nodes(&db, "alice").await.unwrap();
        assert_eq!(rows.len(), 1, "{rows:?}");
        assert_eq!((rows[0].id.as_str(), rows[0].device_did.to_string(), rows[0].paired_at), ("laptop", spelled, 5));
    }
}

/// What a write is refused with where the derivation's string for its key is
/// already the DID of `user_id`'s row `label` beside another key. The label is
/// printed as prose prints a name ([`kotton_wire::note::quoted`],
/// kottonllc/kotton#597, 43A); `did` is the derivation, one plain word.
fn under_another_key(label: &str, did: &str) -> String {
    format!(
        "this person pairs {} under {did}, this key's did:key, beside another key, and \
         keeps it as that; nothing was written (`device revoke {did}` removes that row)",
        kotton_wire::note::quoted(label)
    )
}

/// The DID [`write_row`] writes `user_id`'s row for `key` under, read on the
/// caller's connection or inside its transaction: the DID the key's row is
/// stored under, or the derivation's string where the key has no row and no
/// row is under that string. `Ok(Err)` is the sentence the write is refused
/// with where that string is a row's DID beside another key.
async fn row_name(
    conn: &mut sqlx::SqliteConnection,
    user_id: &str,
    key: &VerifyingKey,
) -> io::Result<Result<String, String>> {
    if let Some(row) = row_for_key(&mut *conn, user_id, key.as_bytes()).await? {
        return Ok(Ok(row.device_did.to_string()));
    }
    let derived = kotton_crypto::DidKeyMethod::from_public_key(key).to_string();
    let beside: Option<String> = sqlx::query_scalar("SELECT id FROM paired_nodes WHERE user_id = ? AND device_did = ?")
        .bind(user_id)
        .bind(&derived)
        .fetch_optional(&mut *conn)
        .await
        .map_err(db_err)?;
    Ok(match beside {
        Some(label) => Err(under_another_key(&label, &derived)),
        None => Ok(derived),
    })
}

/// **Whether [`insert_paired_node`] would refuse `user_id`'s row for `key`,
/// read and nothing written**: `Some` with the sentence the write is refused
/// with, `None` where the write takes the key's row or writes a new one.
///
/// The rule is the writer's own: [`write_row`] names the row through the same
/// read. So a ceremony that asks this before it keeps anything
/// (`super::nodes::finalize_enrolled_node`, and the joiner's completion in
/// `kotton_device::users::pairing`) keeps nothing the store refuses: no key, no
/// key log, no row. The write makes the read again inside its transaction, so
/// a row written between the two is refused there as well. No writer of this
/// build stores the refused shape — every writer names a new row by its own
/// key's derivation or keeps the key's row — so between the read and the write
/// the offending row can only be removed.
pub async fn row_refused_for(db: &SqlitePool, user_id: &str, key: &VerifyingKey) -> io::Result<Option<String>> {
    let mut conn = db.acquire().await.map_err(db_err)?;
    Ok(row_name(&mut conn, user_id, key).await?.err())
}

/// The write [`insert_paired_node`] and [`add_paired_node_if_absent`] make,
/// inside the caller's transaction.
#[allow(clippy::too_many_arguments)]
async fn write_row(
    conn: &mut sqlx::SqliteConnection,
    id: &str,
    user_id: &str,
    key: &VerifyingKey,
    addresses_json: &str,
    now: i64,
    posture: Option<&str>,
) -> io::Result<PairedNode> {
    let public_key = key.as_bytes().as_slice();
    // The row's name: the DID the key's row is stored under, or the derivation's
    // string where the key has no row and no row is under that string.
    let device_did = row_name(&mut *conn, user_id, key).await?.map_err(io::Error::other)?;
    // `INSERT OR REPLACE` rewrites the whole row, and callers that only know an
    // address (`peer_add`) know no posture. A posture already projected for
    // this node is kept rather than erased: erasing it turned a blind node into
    // a node of unknown posture, which no delivery would then reach. The row
    // under this DID, where there is one, holds this key: the DID is the key's
    // row's or a string no row is under. The relay the peer was last known to
    // reserve at is kept.
    let existing: Option<(Option<String>, Option<String>)> =
        sqlx::query_as("SELECT posture, relay_url FROM paired_nodes WHERE user_id = ? AND device_did = ?")
            .bind(user_id)
            .bind(&device_did)
            .fetch_optional(&mut *conn)
            .await
            .map_err(db_err)?;
    let (existing_posture, existing_relay) = existing.unwrap_or((None, None));
    let posture: Option<String> = posture.map(str::to_string).or(existing_posture);
    sqlx::query(
        "INSERT OR REPLACE INTO paired_nodes \
         (id, user_id, device_did, public_key, addresses, paired_at, posture, relay_url) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(id)
    .bind(user_id)
    .bind(&device_did)
    .bind(public_key)
    .bind(addresses_json)
    .bind(now)
    .bind(posture)
    .bind(existing_relay)
    .execute(&mut *conn)
    .await
    .map_err(db_err)?;
    // A drive is reached through the node that carries the vault's key
    // (`super::drives`), and its record shows the label that node is under.
    sqlx::query("UPDATE drives SET node_id = ? WHERE user_id = ? AND vault_key = ?")
        .bind(id)
        .bind(user_id)
        .bind(public_key)
        .execute(&mut *conn)
        .await
        .map_err(db_err)?;
    let row = sqlx::query(&format!(
        "SELECT {NODE_COLUMNS} FROM paired_nodes WHERE user_id = ? AND device_did = ?"
    ))
    .bind(user_id)
    .bind(&device_did)
    .fetch_one(&mut *conn)
    .await
    .map_err(db_err)?;
    node_of(&row)
}

/// Store one row exactly as given, as an earlier build could have stored it: a
/// DID that is not its key's derivation, bytes the Ed25519 rule refuses, a
/// second row for a key. A plain `INSERT`: no drive is touched, and no row is
/// replaced.
///
/// **For a test whose subject is such a row, and nothing else.** No writer of
/// this build stores one ([`insert_paired_node`] takes a key and makes the
/// name), so a test of a reader, a removal or a readout over an earlier
/// build's row has it stored here (kottonllc/kotton#597, 68A). Compiled only
/// under `test-support`, which no packed binary's closure turns on:
/// `cargo xtask ship-check` refuses one that does.
#[cfg(any(test, feature = "test-support"))]
#[allow(clippy::too_many_arguments)]
pub async fn seed_paired_node_as_stored(
    db: &SqlitePool,
    id: &str,
    user_id: &str,
    device_did: &str,
    public_key: &[u8],
    addresses_json: &str,
    now: i64,
    posture: Option<&str>,
) -> io::Result<()> {
    sqlx::query(
        "INSERT INTO paired_nodes \
         (id, user_id, device_did, public_key, addresses, paired_at, posture, relay_url) \
         VALUES (?, ?, ?, ?, ?, ?, ?, NULL)",
    )
    .bind(id)
    .bind(user_id)
    .bind(device_did)
    .bind(public_key)
    .bind(addresses_json)
    .bind(now)
    .bind(posture)
    .execute(db)
    .await
    .map_err(db_err)?;
    Ok(())
}

/// Remove `user_id`'s drive record for `vault_key` when no row of theirs
/// carries that key any more: a drive with no node to reach it through is not
/// one this device has.
async fn drop_unreachable_drive(
    conn: &mut sqlx::SqliteConnection,
    user_id: &str,
    vault_key: &[u8],
) -> io::Result<()> {
    sqlx::query(
        "DELETE FROM drives WHERE user_id = ? AND vault_key = ? \
         AND NOT EXISTS (SELECT 1 FROM paired_nodes WHERE user_id = ? AND public_key = ?)",
    )
    .bind(user_id)
    .bind(vault_key)
    .bind(user_id)
    .bind(vault_key)
    .execute(conn)
    .await
    .map_err(db_err)?;
    Ok(())
}

/// Refresh a paired node's `addresses` to a single freshly-observed,
/// directly-dialable address.
///
/// Called after a successful direct/hole-punched operational connect so the
/// *next* dial tries the live address first, instead of re-timing-out on the
/// stale enrollment-bootstrap address (implements the `PairedNode::addresses`
/// "updated on each successful connect" contract).
/// A no-op (zero rows) if the node is not paired to this user — the caller
/// treats it as best-effort and does not fail the connection on a miss.
pub async fn update_paired_node_address(
    db: &Arc<SqlitePool>,
    user_id: &str,
    device_did: &str,
    addr: SocketAddr,
) -> io::Result<()> {
    let addresses_json = serde_json::to_string(&vec![addr]).map_err(json_err)?;
    sqlx::query("UPDATE paired_nodes SET addresses = ? WHERE user_id = ? AND device_did = ?")
        .bind(addresses_json)
        .bind(user_id)
        .bind(device_did)
        .execute(db.as_ref())
        .await
        .map_err(db_err)?;
    Ok(())
}

/// Point the row `user_id` already holds for `public_key` at `addresses_json`, as
/// of `now`, and return it as it then stands; `Ok(None)`, with nothing written,
/// when no row of theirs holds the key.
///
/// **The row is found by its bytes, and nothing else of it changes.** Its DID
/// stays as stored, whatever string that is (a row is its bytes',
/// kottonllc/kotton#597, 5B), and so do its label, its posture and the relay it
/// was last known at; no row is added. Where two of the person's rows hold the
/// key it is the one [`reached_through`] gives. A drive under the key shows the
/// row's label, as [`insert_paired_node`] keeps it.
pub async fn readdress_paired_node_for_key(
    db: &Arc<SqlitePool>,
    user_id: &str,
    public_key: &[u8; 32],
    addresses_json: &str,
    now: i64,
) -> io::Result<Option<PairedNode>> {
    let mut tx = kotton_record::immediate::Immediate::begin(db).await?;
    let Some(row) = row_for_key(tx.conn(), user_id, public_key).await? else {
        return Ok(None);
    };
    let (device_did, id) = (row.device_did.to_string(), row.id);
    sqlx::query("UPDATE paired_nodes SET addresses = ?, paired_at = ? WHERE user_id = ? AND device_did = ?")
        .bind(addresses_json)
        .bind(now)
        .bind(user_id)
        .bind(&device_did)
        .execute(tx.conn())
        .await
        .map_err(db_err)?;
    sqlx::query("UPDATE drives SET node_id = ? WHERE user_id = ? AND vault_key = ?")
        .bind(&id)
        .bind(user_id)
        .bind(public_key.as_slice())
        .execute(tx.conn())
        .await
        .map_err(db_err)?;
    let node = sqlx::query(&format!(
        "SELECT {NODE_COLUMNS} FROM paired_nodes WHERE user_id = ? AND device_did = ?"
    ))
    .bind(user_id)
    .bind(&device_did)
    .fetch_one(tx.conn())
    .await
    .map_err(db_err)?;
    let node = node_of(&node)?;
    tx.commit().await?;
    Ok(Some(node))
}

/// Record the relay a paired node told us it reserves at, so the
/// next dial that cannot go direct goes there. `None` clears it.
pub async fn update_paired_node_relay(
    db: &Arc<SqlitePool>,
    user_id: &str,
    device_did: &str,
    relay_url: Option<&str>,
) -> io::Result<()> {
    sqlx::query("UPDATE paired_nodes SET relay_url = ? WHERE user_id = ? AND device_did = ?")
        .bind(relay_url)
        .bind(user_id)
        .bind(device_did)
        .execute(db.as_ref())
        .await
        .map_err(db_err)?;
    Ok(())
}

/// The posture a `paired_nodes` row records, as [`PairedNode::posture`] carries
/// it: the text as written, `None` for a row with none. Text this build does
/// not recognise is kept as it is — said, and never read as none, which a
/// reader may take for a row from before postures
/// (`kotton_peer::relay_keys::offers_from` reads it as not *full*).
fn row_posture(row: &sqlx::sqlite::SqliteRow) -> Option<String> {
    let text = row.get::<Option<String>, _>("posture")?;
    if kotton_schemas::membership::Posture::parse(&text).is_none() {
        tracing::warn!(posture = %text, "a paired node's row records a posture this build does not recognise");
    }
    Some(text)
}

/// One `paired_nodes` row, as the wire carries it.
fn node_of(row: &sqlx::sqlite::SqliteRow) -> io::Result<PairedNode> {
    let device_did = Did::parse(&row.get::<String, _>("device_did")).map_err(did_err)?;
    let public_key: [u8; 32] = row
        .get::<Vec<u8>, _>("public_key")
        .try_into()
        .map_err(|_| io::Error::other("corrupt public_key length in paired_nodes"))?;
    let addresses: Vec<SocketAddr> =
        serde_json::from_str(&row.get::<String, _>("addresses")).map_err(json_err)?;
    Ok(PairedNode {
        id: row.get("id"),
        device_did,
        public_key,
        paired_at: row.get("paired_at"),
        addresses,
        relay_url: row.get::<Option<String>, _>("relay_url").filter(|u| !u.is_empty()),
        posture: row_posture(row),
    })
}

const NODE_COLUMNS: &str = "id, device_did, public_key, paired_at, addresses, relay_url, posture";

/// `user_id`'s rows, in the one order ([`listed_before`]): for each key, the
/// row it is reached through ([`reached_through`]) is the first listed of
/// those that hold it.
pub async fn list_paired_nodes(
    db: &Arc<SqlitePool>,
    user_id: &str,
) -> io::Result<Vec<PairedNode>> {
    let rows = sqlx::query(&format!("SELECT {NODE_COLUMNS} FROM paired_nodes WHERE user_id = ?"))
        .bind(user_id)
        .fetch_all(db.as_ref())
        .await
        .map_err(db_err)?;
    let mut nodes = rows.iter().map(node_of).collect::<io::Result<Vec<_>>>()?;
    nodes.sort_by(listed_before);
    Ok(nodes)
}

/// `user_id`'s row for the node `device_did`: the one row the key names.
pub async fn get_paired_node(
    db: &Arc<SqlitePool>,
    user_id: &str,
    device_did: &str,
) -> io::Result<Option<PairedNode>> {
    let row = sqlx::query(&format!(
        "SELECT {NODE_COLUMNS} FROM paired_nodes WHERE user_id = ? AND device_did = ?"
    ))
    .bind(user_id)
    .bind(device_did)
    .fetch_optional(db.as_ref())
    .await
    .map_err(db_err)?;
    row.as_ref().map(node_of).transpose()
}

/// `user_id`'s row carrying `public_key`, the node a drive under that key is
/// reached through ([`super::drives`]): the one [`reached_through`] gives when
/// two carry it.
pub async fn paired_node_for_key(
    db: &Arc<SqlitePool>,
    user_id: &str,
    public_key: &[u8; 32],
) -> io::Result<Option<PairedNode>> {
    let mut conn = db.acquire().await.map_err(db_err)?;
    row_for_key(&mut conn, user_id, public_key).await
}

/// The row `name` names among `user_id`'s rows: its DID as stored, or the label
/// it is shown under when one row carries it, each taken whole and by equality.
/// This is the rows half of the one resolver a verb a person names a node in
/// goes through, `super::nodes::node_named` (kottonllc/kotton#610).
/// A label is a name, not a key (`migrations/0027_paired_nodes_per_person.sql`),
/// so two of the person's rows may carry one; such a label is refused with the
/// DIDs that tell them apart, never resolved to whichever row came first.
/// `Ok(None)` when it names none.
pub async fn paired_node_named(
    db: &Arc<SqlitePool>,
    user_id: &str,
    name: &str,
) -> io::Result<Option<PairedNode>> {
    if let Some(node) = get_paired_node(db, user_id, name).await? {
        return Ok(Some(node));
    }
    let rows = sqlx::query(&format!(
        "SELECT {NODE_COLUMNS} FROM paired_nodes WHERE user_id = ? AND id = ? ORDER BY device_did"
    ))
    .bind(user_id)
    .bind(name)
    .fetch_all(db.as_ref())
    .await
    .map_err(db_err)?;
    let mut nodes = rows.iter().map(node_of).collect::<io::Result<Vec<_>>>()?;
    match nodes.len() {
        0 | 1 => Ok(nodes.pop()),
        n => Err(io::Error::other(format!(
            "'{name}' is the label of {n} of your nodes ({}); name the one you mean by its DID",
            nodes.iter().map(|n| n.device_did.to_string()).collect::<Vec<_>>().join(", ")
        ))),
    }
}

/// The name a verb takes to `row` among `rows`, the person's rows, as the
/// surface reads it from a typed line: its label where the label is
/// [`kotton_wire::note::one_plain_word`] and [`paired_node_named`] takes it to
/// this row and no other, and its DID as stored otherwise. The resolver reads a
/// name as a DID first, so a label that is a row's DID finds that row and is no
/// name for another; and a label two rows carry finds neither. A DID as stored
/// that is not one plain word gets a sentence that names the verb and the name
/// it takes, with no command in it ([`kotton_wire::note::sentence`], 23A). One rule, the resolver's at the
/// surface's parser, read over rows already in hand (kottonllc/kotton#597, 20A).
pub fn name_of(rows: &[PairedNode], row: &PairedNode) -> String {
    let label = row.id.as_str();
    let a_did = rows.iter().any(|r| r.device_did.to_string() == label);
    let carried = rows.iter().filter(|r| r.id == label).count();
    if kotton_wire::note::one_plain_word(label) && !a_did && carried == 1 {
        label.to_string()
    } else {
        row.device_did.to_string()
    }
}

/// The note the node listing carries for `row`, one of `rows` (the person's),
/// or `None` for a row whose DID is its key's `did:key`
/// ([`kotton_wire::note`]): a row whose bytes the Ed25519 rule refuses names no
/// key; a row whose bytes pass under a `did:key` that is not theirs stands by
/// them (5B). A DID of another method beside a key is not read here. Made
/// from the row and nothing else.
pub fn note_of(rows: &[PairedNode], row: &PairedNode) -> Option<kotton_wire::note::RowNote> {
    use kotton_wire::note::{NoteKind, RowNote};
    match kotton_crypto::DidKeyMethod::from_public_key_bytes(&row.public_key) {
        Err(_) => Some(RowNote::names_no_key(name_of(rows, row))),
        Ok(did_key) if row.device_did.method() == "key" && did_key.to_string() != row.device_did.to_string() => {
            Some(RowNote {
                name: name_of(rows, row),
                is: NoteKind::StandsByBytes { did_key: did_key.to_string(), stored: row.device_did.to_string() },
            })
        }
        Ok(_) => None,
    }
}

/// [`note_of`] for every row of `rows`, in their order.
pub fn notes_of(rows: &[PairedNode]) -> Vec<kotton_wire::note::RowNote> {
    rows.iter().filter_map(|r| note_of(rows, r)).collect()
}

/// Delete `user_id`'s row for the node `device_did`, and a drive reached
/// through it ([`super::drives`]) that no other row of theirs still carries
/// the key of: a drive with no node to reach it through is not one this device
/// has. Returns `true` if a node row was removed.
pub(crate) async fn delete_paired_node(
    db: &Arc<SqlitePool>,
    user_id: &str,
    device_did: &str,
) -> io::Result<bool> {
    let mut tx = kotton_record::immediate::Immediate::begin(db).await?;
    let key: Option<Vec<u8>> =
        sqlx::query_scalar("SELECT public_key FROM paired_nodes WHERE user_id = ? AND device_did = ?")
            .bind(user_id)
            .bind(device_did)
            .fetch_optional(tx.conn())
            .await
            .map_err(db_err)?;
    let Some(key) = key else {
        tx.end("ROLLBACK").await?;
        return Ok(false);
    };
    sqlx::query("DELETE FROM paired_nodes WHERE user_id = ? AND device_did = ?")
        .bind(user_id)
        .bind(device_did)
        .execute(tx.conn())
        .await
        .map_err(db_err)?;
    drop_unreachable_drive(tx.conn(), user_id, &key).await?;
    tx.commit().await?;
    Ok(true)
}

/// Every person here who pairs `public_key`, by name, in name order. Rows are
/// each person's (`migrations/0027_paired_nodes_per_person.sql`), so two
/// people here may pair one key (two tenants of one vault on a shared device,
/// or one gateway two people enrolled), and a reader that knows the key and no
/// person is handed all of them rather than one. What a key *is* to a person —
/// its posture, and so what it may ask for them — is read for the person a
/// request names, by [`paired_posture_for_user`]; nothing here decides it.
pub async fn paired_users_for_pubkey(
    db: &Arc<SqlitePool>,
    public_key: &[u8; 32],
) -> io::Result<Vec<String>> {
    sqlx::query_scalar("SELECT DISTINCT user_id FROM paired_nodes WHERE public_key = ? ORDER BY user_id")
        .bind(public_key.as_slice())
        .fetch_all(db.as_ref())
        .await
        .map_err(db_err)
}

/// The posture `user_id` pairs `public_key` under: `None` when they pair it
/// nowhere, `Some(None)` for a row naming no posture. This is the read that
/// decides what a key may ask *for this person* — the peer path's gateway
/// confinement and `NodeRelay`'s own-device check both read it, for the person
/// the request names; another person's row for the same key says nothing of
/// what it is to this one.
///
/// Where two rows of this person's hold the key, which only an earlier build
/// can have stored, the narrowest of what they say answers ([`narrowest`]):
/// within one person's rows, the narrower verb wins. The answer is a function
/// of the postures alone; it reads neither a row's DID nor its `paired_at`, so
/// it is the same however the rows are spelled and whenever they were written.
/// It picks no row to reach: the row a key is reached through is
/// [`reached_through`]'s, and may be another (kottonllc/kotton#597).
pub async fn paired_posture_for_user(
    db: &Arc<SqlitePool>,
    public_key: &[u8; 32],
    user_id: &str,
) -> io::Result<Option<Option<String>>> {
    let postures: Vec<Option<String>> =
        sqlx::query_scalar("SELECT posture FROM paired_nodes WHERE public_key = ? AND user_id = ?")
            .bind(public_key.as_slice())
            .bind(user_id)
            .fetch_all(db.as_ref())
            .await
            .map_err(db_err)?;
    Ok(narrowest(postures.iter().map(Option::as_deref)).map(|p| p.map(str::to_string)))
}

/// The narrowest of the postures a person's rows for one key say, `None` for
/// no rows; `Some(None)` where the narrowest is a row naming none. Narrowest
/// first: `gateway`; `blind-storage`; `cosigner`; text this build does not
/// recognise, the least by its bytes; `full`; no posture.
///
/// `gateway` is first because a gateway holds nothing and is postured so
/// pairing gives it no reach (`Posture::Gateway`). The postures after it up to
/// `full` are those its readers take as not `full`, and so are given no key at
/// `NodeRelay`; text this build does not recognise is among them, as every
/// reader already reads it (`kotton_peer::relay_keys::offers_from`).
pub fn narrowest<'a>(postures: impl IntoIterator<Item = Option<&'a str>>) -> Option<Option<&'a str>> {
    /// Where `posture` stands, narrowest first; ties only between texts this
    /// build does not recognise, which the text itself orders.
    fn place(posture: Option<&str>) -> (u8, &str) {
        match posture.map(|text| (Posture::parse(text), text)) {
            Some((Some(Posture::Gateway), _)) => (0, ""),
            Some((Some(Posture::BlindStorage), _)) => (1, ""),
            Some((Some(Posture::Cosigner), _)) => (2, ""),
            Some((None, text)) => (3, text),
            Some((Some(Posture::Full), _)) => (4, ""),
            None => (5, ""),
        }
    }
    postures.into_iter().min_by(|a, b| place(*a).cmp(&place(*b)))
}

/// Return `true` if the peer's raw Ed25519 public key is recorded in `paired_nodes` for `user_id`.
///
/// Used by `handle_peer_request` to enforce that a peer can only access data
/// belonging to users on whose behalf it was actually paired.
///
/// Keyed on `public_key` (binary) rather than `device_did` because the TLS
/// handshake presents the device's operational signing key, which is what the
/// key names; a DID recorded beside it may name another.
pub async fn is_pubkey_paired_to_user(
    db: &Arc<SqlitePool>,
    public_key: &[u8; 32],
    user_id: &str,
) -> io::Result<bool> {
    let row =
        sqlx::query("SELECT 1 FROM paired_nodes WHERE public_key = ? AND user_id = ? LIMIT 1")
            .bind(public_key.as_slice())
            .bind(user_id)
            .fetch_optional(db.as_ref())
            .await
            .map_err(db_err)?;
    Ok(row.is_some())
}

// ---------------------------------------------------------------------------
// operator_key — this node's operator credentials, by their public halves
// ---------------------------------------------------------------------------

/// Whether `public_key` is this node's operator credential. Read per request,
/// as `is_pubkey_paired_to_user` is, so a revocation is seen by the next frame.
pub async fn is_operator_key(db: &SqlitePool, public_key: &[u8; 32]) -> io::Result<bool> {
    let row = sqlx::query("SELECT 1 FROM operator_key WHERE public_key = ? LIMIT 1")
        .bind(public_key.as_slice())
        .fetch_optional(db)
        .await
        .map_err(db_err)?;
    Ok(row.is_some())
}

/// Every operator key this node admits — none on a device, and on a vault the
/// set its door enrolled (a device has operators, not an operator: a vault or
/// relay the person operates admits several, each its own holder's) —
/// for the allowlist the handshake reads.
pub async fn operator_keys(db: &SqlitePool) -> io::Result<Vec<[u8; 32]>> {
    let rows = sqlx::query("SELECT public_key FROM operator_key ORDER BY enrolled_at, public_key")
        .fetch_all(db)
        .await
        .map_err(db_err)?;
    Ok(rows
        .into_iter()
        .filter_map(|r| r.get::<Vec<u8>, _>("public_key").try_into().ok())
        .collect())
}

/// Add `public_key` to this node's operator keys. The others stay: enrolling a
/// second operator is not handing the standing on. Returns whether the key is
/// new — enrolling one already there changes nothing, its first enrolment's
/// time included.
pub async fn enrol_operator_key(db: &SqlitePool, public_key: &[u8; 32]) -> io::Result<bool> {
    let done = sqlx::query("INSERT OR IGNORE INTO operator_key (public_key, enrolled_at) VALUES (?, ?)")
        .bind(public_key.as_slice())
        .bind(kotton_common::time::now_secs())
        .execute(db)
        .await
        .map_err(db_err)?;
    Ok(done.rows_affected() == 1)
}

/// What revoking one operator key did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Revoked {
    /// It was enrolled and is gone; the caller takes it out of the allowlist in
    /// the same step.
    Gone,
    /// It was not one of this node's operators.
    NotEnrolled,
    /// It is the last operator, and stays: an operator set is never emptied
    /// while the instance runs.
    Last,
}

/// Delete one operator key, unless it is the last. One statement, so no other
/// revocation can interleave and leave the set empty.
pub async fn revoke_operator_key(db: &SqlitePool, public_key: &[u8; 32]) -> io::Result<Revoked> {
    let done = sqlx::query(
        "DELETE FROM operator_key WHERE public_key = ? \
         AND EXISTS (SELECT 1 FROM operator_key WHERE public_key != ?)",
    )
    .bind(public_key.as_slice())
    .bind(public_key.as_slice())
    .execute(db)
    .await
    .map_err(db_err)?;
    if done.rows_affected() == 1 {
        Ok(Revoked::Gone)
    } else if is_operator_key(db, public_key).await? {
        Ok(Revoked::Last)
    } else {
        Ok(Revoked::NotEnrolled)
    }
}

/// Delete every operator key but `keep`. `None` — and nothing deleted — when
/// `keep` is not enrolled, so the set is never emptied.
/// Returns what was deleted, for the caller to take out of the allowlist in the
/// same step. One statement, as [`revoke_operator_key`] is.
pub async fn revoke_operator_keys_but(db: &SqlitePool, keep: &[u8; 32]) -> io::Result<Option<Vec<[u8; 32]>>> {
    let before = operator_keys(db).await?;
    sqlx::query(
        "DELETE FROM operator_key WHERE public_key != ? \
         AND EXISTS (SELECT 1 FROM operator_key WHERE public_key = ?)",
    )
    .bind(keep.as_slice())
    .bind(keep.as_slice())
    .execute(db)
    .await
    .map_err(db_err)?;
    if !is_operator_key(db, keep).await? {
        return Ok(None);
    }
    let after = operator_keys(db).await?;
    Ok(Some(before.into_iter().filter(|k| !after.contains(k)).collect()))
}

// ---------------------------------------------------------------------------
// operator_acts — which operator key said which of the landlord's verbs
// ---------------------------------------------------------------------------

/// One act an operator key said over the wire, as the vault kept it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperatorAct {
    /// The key the connection authenticated as — the act's signer.
    pub public_key: [u8; 32],
    /// The request's variant name (`DeviceInvite`, `Tenants`, `SetQuota`,
    /// `DropTenant`).
    pub verb: String,
    /// The pool it named; empty for `Tenants`, which names none.
    pub pool: String,
    /// Whether the vault answered it without an error.
    pub ok: bool,
    pub at: i64,
}

/// Keep one operator act, under the key that said it, before it runs:
/// `ok` starts false and [`operator_act_done`] sets it once the vault has
/// answered. Returns the row's id.
pub async fn record_operator_act(
    db: &SqlitePool,
    public_key: &[u8; 32],
    verb: &str,
    pool: &str,
) -> io::Result<i64> {
    let done = sqlx::query("INSERT INTO operator_acts (public_key, verb, pool, ok, at) VALUES (?, ?, ?, 0, ?)")
        .bind(public_key.as_slice())
        .bind(verb)
        .bind(pool)
        .bind(kotton_common::time::now_secs())
        .execute(db)
        .await
        .map_err(db_err)?;
    Ok(done.last_insert_rowid())
}

/// Mark a kept act as answered without an error.
pub async fn operator_act_done(db: &SqlitePool, id: i64) -> io::Result<()> {
    sqlx::query("UPDATE operator_acts SET ok = 1 WHERE id = ?")
        .bind(id)
        .execute(db)
        .await
        .map_err(db_err)?;
    Ok(())
}

/// Every operator act this node kept, oldest first.
pub async fn operator_acts(db: &SqlitePool) -> io::Result<Vec<OperatorAct>> {
    let rows = sqlx::query("SELECT public_key, verb, pool, ok, at FROM operator_acts ORDER BY id")
        .fetch_all(db)
        .await
        .map_err(db_err)?;
    Ok(rows
        .into_iter()
        .filter_map(|r| {
            Some(OperatorAct {
                public_key: r.get::<Vec<u8>, _>("public_key").try_into().ok()?,
                verb: r.get("verb"),
                pool: r.get("pool"),
                ok: r.get::<bool, _>("ok"),
                at: r.get("at"),
            })
        })
        .collect())
}

// ---------------------------------------------------------------------------
// ephemeral_sessions
// ---------------------------------------------------------------------------

pub(crate) async fn insert_ephemeral_session(
    db: &Arc<SqlitePool>,
    session_id: &str,
    user_id: &str,
    guest_did: &str,
    guest_pubkey: &[u8],
    grant_json: &str,
    now: i64,
) -> io::Result<()> {
    sqlx::query(
        "INSERT INTO ephemeral_sessions \
         (id, user_id, guest_did, guest_pubkey, grant_json, issued_at, revoked) \
         VALUES (?, ?, ?, ?, ?, ?, 0)",
    )
    .bind(session_id)
    .bind(user_id)
    .bind(guest_did)
    .bind(guest_pubkey)
    .bind(grant_json)
    .bind(now)
    .execute(db.as_ref())
    .await
    .map_err(db_err)?;
    Ok(())
}

pub(crate) async fn list_ephemeral_sessions(
    db: &Arc<SqlitePool>,
    user_id: &str,
) -> io::Result<Vec<EphemeralSession>> {
    let rows = sqlx::query(
        "SELECT id, guest_did, guest_pubkey, grant_json, issued_at, revoked \
         FROM ephemeral_sessions WHERE user_id = ? ORDER BY issued_at DESC",
    )
    .bind(user_id)
    .fetch_all(db.as_ref())
    .await
    .map_err(db_err)?;

    let mut sessions = Vec::with_capacity(rows.len());
    for row in rows {
        let guest_did: String = row.get("guest_did");
        let pk_bytes: Vec<u8> = row.get("guest_pubkey");
        let grant_json: String = row.get("grant_json");
        let revoked: i64 = row.get("revoked");

        let public_key: [u8; 32] = pk_bytes
            .try_into()
            .map_err(|_| io::Error::other("corrupt guest_pubkey in ephemeral_sessions"))?;

        sessions.push(EphemeralSession {
            id: row.get("id"),
            guest_did: Did::parse(&guest_did).map_err(did_err)?,
            guest_public_key: public_key,
            grant: serde_json::from_str::<GrantEnvelope>(&grant_json).map_err(json_err)?,
            issued_at: row.get("issued_at"),
            revoked: revoked != 0,
            wrapped_deks: std::collections::HashMap::new(),
        });
    }
    Ok(sessions)
}

/// Return the active (non-revoked) ephemeral session for a given guest DID and
/// user, if one exists.
///
/// Used by `handle_peer_request` to authorise peers that connected via an
/// ephemeral session ticket rather than a full `pair start / accept` ceremony.
pub async fn find_ephemeral_session_by_guest_did(
    db: &Arc<SqlitePool>,
    guest_did: &str,
    user_id: &str,
) -> io::Result<Option<EphemeralSession>> {
    let row_opt = sqlx::query(
        "SELECT id, guest_did, guest_pubkey, grant_json, issued_at, revoked \
         FROM ephemeral_sessions \
         WHERE guest_did = ? AND user_id = ? AND revoked = 0 \
         LIMIT 1",
    )
    .bind(guest_did)
    .bind(user_id)
    .fetch_optional(db.as_ref())
    .await
    .map_err(db_err)?;

    match row_opt {
        None => Ok(None),
        Some(row) => {
            let guest_did_str: String = row.get("guest_did");
            let pk_bytes: Vec<u8> = row.get("guest_pubkey");
            let grant_json: String = row.get("grant_json");
            let revoked: i64 = row.get("revoked");

            let public_key: [u8; 32] = pk_bytes
                .try_into()
                .map_err(|_| io::Error::other("corrupt guest_pubkey in ephemeral_sessions"))?;

            Ok(Some(EphemeralSession {
                id: row.get("id"),
                guest_did: Did::parse(&guest_did_str).map_err(did_err)?,
                guest_public_key: public_key,
                grant: serde_json::from_str::<GrantEnvelope>(&grant_json).map_err(json_err)?,
                issued_at: row.get("issued_at"),
                revoked: revoked != 0,
                wrapped_deks: std::collections::HashMap::new(),
            }))
        }
    }
}

/// Revoke a session. Returns `true` if the row was found.
pub(crate) async fn revoke_session(
    db: &Arc<SqlitePool>,
    user_id: &str,
    session_id: &str,
) -> io::Result<bool> {
    let result =
        sqlx::query("UPDATE ephemeral_sessions SET revoked = 1 WHERE user_id = ? AND id = ?")
            .bind(user_id)
            .bind(session_id)
            .execute(db.as_ref())
            .await
            .map_err(db_err)?;
    Ok(result.rows_affected() > 0)
}

/// Load all revoked session IDs into memory.
///
/// Called at startup to seed the in-memory revocation set so that
/// `handle_peer_request` can skip DB queries for already-revoked sessions.
pub async fn list_revoked_session_ids(
    db: &Arc<SqlitePool>,
) -> io::Result<HashSet<String>> {
    let rows = sqlx::query("SELECT id FROM ephemeral_sessions WHERE revoked = 1")
        .fetch_all(db.as_ref())
        .await
        .map_err(db_err)?;
    Ok(rows.into_iter().map(|r| r.get::<String, _>("id")).collect())
}

// ---------------------------------------------------------------------------
// mount_configs
// ---------------------------------------------------------------------------

// Allowed: one argument per `mount_configs` column it writes, as `insert_paired_node` above.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn upsert_mount(
    db: &Arc<SqlitePool>,
    user_id: &str,
    node_id: &str,
    remote_path: &str,
    local_path: &str,
    cache_budget_bytes: Option<u64>,
    pins_json: &str,
    now: i64,
) -> io::Result<()> {
    sqlx::query(
        "INSERT INTO mount_configs \
         (user_id, node_id, remote_path, local_path, cache_budget_bytes, pins, mounted_at) \
         VALUES (?, ?, ?, ?, ?, ?, ?) \
         ON CONFLICT(user_id, local_path) DO UPDATE SET \
           node_id=excluded.node_id, remote_path=excluded.remote_path, \
           cache_budget_bytes=excluded.cache_budget_bytes, pins=excluded.pins, \
           mounted_at=excluded.mounted_at",
    )
    .bind(user_id)
    .bind(node_id)
    .bind(remote_path)
    .bind(local_path)
    .bind(cache_budget_bytes.map(|b| b as i64))
    .bind(pins_json)
    .bind(now)
    .execute(db.as_ref())
    .await
    .map_err(db_err)?;
    Ok(())
}

pub(crate) async fn list_mounts(
    db: &Arc<SqlitePool>,
    user_id: &str,
) -> io::Result<Vec<MountConfig>> {
    let rows = sqlx::query(
        "SELECT node_id, remote_path, local_path, cache_budget_bytes, pins, mounted_at \
         FROM mount_configs WHERE user_id = ? ORDER BY mounted_at DESC",
    )
    .bind(user_id)
    .fetch_all(db.as_ref())
    .await
    .map_err(db_err)?;

    let mut mounts = Vec::with_capacity(rows.len());
    for row in rows {
        let pins_json: String = row.get("pins");
        let pins: Vec<String> = serde_json::from_str(&pins_json).map_err(json_err)?;
        let cb: Option<i64> = row.get("cache_budget_bytes");
        mounts.push(MountConfig {
            node_id: row.get("node_id"),
            remote_path: row.get("remote_path"),
            local_path: row.get("local_path"),
            cache_budget_bytes: cb.map(|v| v as u64),
            pins,
            mounted_at: row.get("mounted_at"),
        });
    }
    Ok(mounts)
}

/// Delete a mount. Returns `true` if a row was removed.
pub(crate) async fn delete_mount(
    db: &Arc<SqlitePool>,
    user_id: &str,
    node_id: &str,
    local_path: &str,
) -> io::Result<bool> {
    let result = sqlx::query(
        "DELETE FROM mount_configs WHERE user_id = ? AND node_id = ? AND local_path = ?",
    )
    .bind(user_id)
    .bind(node_id)
    .bind(local_path)
    .execute(db.as_ref())
    .await
    .map_err(db_err)?;
    Ok(result.rows_affected() > 0)
}
