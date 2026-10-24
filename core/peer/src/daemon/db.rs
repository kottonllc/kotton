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
//! **A `paired_nodes` row is one person's**, keyed by that person and the
//! node's DID (`migrations/0027_paired_nodes_per_person.sql`). Its `id` is the
//! label the person sees it under and keys nothing: a label may come from
//! elsewhere (the name a device announced at a join, a drive's label handed at
//! one), so a write under it reaches no other row, and two of one person's
//! rows may carry it. What names a row is [`get_paired_node`]; a verb a person
//! names a node in resolves the name through [`paired_node_named`], which
//! refuses a label two rows carry rather than pick one.

use kotton_wire::did::{Did, DidError};
use kotton_wire::peer::{EphemeralSession, MountConfig, PairedNode};
use kotton_wire::GrantEnvelope;
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

// Eight columns, eight arguments: a row, not a design.
/// Write `user_id`'s row for the node `device_did`, or rewrite the row they
/// already hold for it. A row is keyed by the person and the node's DID
/// (`migrations/0027_paired_nodes_per_person.sql`), and `id` is the label it is
/// shown under, which keys nothing: so this write reaches no other person's
/// row, and no row of this person's under another DID, whatever label it
/// carries.
#[allow(clippy::too_many_arguments)]
pub async fn insert_paired_node(
    db: &Arc<SqlitePool>,
    id: &str,
    user_id: &str,
    device_did: &str,
    public_key: &[u8],
    addresses_json: &str,
    now: i64,
    posture: Option<&str>,
) -> io::Result<()> {
    // One transaction: the row, and the drive it may be reached for
    // (`super::drives`), are written together or not at all, so no reader sees
    // a row that says one thing and a record that says another.
    let mut tx = db.begin().await.map_err(db_err)?;
    // `INSERT OR REPLACE` rewrites the whole row, and callers that only know an
    // address (`peer_add`) know no posture. A posture already projected for
    // this node is kept rather than erased: erasing it turned a blind node into
    // a node of unknown posture, which no delivery would then reach. **Only for
    // the same key**: a posture is a fact about the node that holds the key, and
    // a DID may be recorded beside a key it does not name (the operational key a
    // device presents, beside its identity's DID), so the row this person held
    // for the DID under another key gives the new key none. The relay the peer
    // was last known to reserve at is kept.
    let existing: Option<(Vec<u8>, Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT public_key, posture, relay_url FROM paired_nodes WHERE user_id = ? AND device_did = ?",
    )
    .bind(user_id)
    .bind(device_did)
    .fetch_optional(&mut *tx)
    .await
    .map_err(db_err)?;
    let (existing_key, existing_posture, existing_relay) = existing.unwrap_or((Vec::new(), None, None));
    let posture: Option<String> = match posture {
        Some(p) => Some(p.to_string()),
        None if existing_key.as_slice() == public_key => existing_posture,
        None => None,
    };
    sqlx::query(
        "INSERT OR REPLACE INTO paired_nodes \
         (id, user_id, device_did, public_key, addresses, paired_at, posture, relay_url) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(id)
    .bind(user_id)
    .bind(device_did)
    .bind(public_key)
    .bind(addresses_json)
    .bind(now)
    .bind(posture)
    .bind(existing_relay)
    .execute(&mut *tx)
    .await
    .map_err(db_err)?;
    // A drive is reached through the node that carries the vault's key
    // (`super::drives`), and its record shows the label that node is under.
    sqlx::query("UPDATE drives SET node_id = ? WHERE user_id = ? AND vault_key = ?")
        .bind(id)
        .bind(user_id)
        .bind(public_key)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;
    // The key this DID's row carried before, when it was another: a drive under
    // that key that no row of this person's still carries has no node left to
    // reach it through.
    if !existing_key.is_empty() && existing_key.as_slice() != public_key {
        drop_unreachable_drive(&mut tx, user_id, &existing_key).await?;
    }
    tx.commit().await.map_err(db_err)
}

/// Remove `user_id`'s drive record for `vault_key` when no row of theirs
/// carries that key any more: a drive with no node to reach it through is not
/// one this device has.
async fn drop_unreachable_drive(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
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
    .execute(&mut **tx)
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

pub async fn list_paired_nodes(
    db: &Arc<SqlitePool>,
    user_id: &str,
) -> io::Result<Vec<PairedNode>> {
    let rows = sqlx::query(&format!(
        "SELECT {NODE_COLUMNS} FROM paired_nodes WHERE user_id = ? ORDER BY paired_at DESC, device_did"
    ))
    .bind(user_id)
    .fetch_all(db.as_ref())
    .await
    .map_err(db_err)?;
    rows.iter().map(node_of).collect()
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
/// reached through ([`super::drives`]); the first by DID when two carry it.
pub async fn paired_node_for_key(
    db: &Arc<SqlitePool>,
    user_id: &str,
    public_key: &[u8; 32],
) -> io::Result<Option<PairedNode>> {
    let row = sqlx::query(&format!(
        "SELECT {NODE_COLUMNS} FROM paired_nodes WHERE user_id = ? AND public_key = ? \
         ORDER BY device_did LIMIT 1"
    ))
    .bind(user_id)
    .bind(public_key.as_slice())
    .fetch_optional(db.as_ref())
    .await
    .map_err(db_err)?;
    row.as_ref().map(node_of).transpose()
}

/// The node `name` names among `user_id`'s rows, for a verb a person names a
/// node in: its DID, or the label it is shown under when one row carries it.
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

/// Delete `user_id`'s row for the node `device_did`, and a drive reached
/// through it ([`super::drives`]) that no other row of theirs still carries
/// the key of: a drive with no node to reach it through is not one this device
/// has. Returns `true` if a node row was removed.
pub(crate) async fn delete_paired_node(
    db: &Arc<SqlitePool>,
    user_id: &str,
    device_did: &str,
) -> io::Result<bool> {
    let mut tx = db.begin().await.map_err(db_err)?;
    let key: Option<Vec<u8>> =
        sqlx::query_scalar("SELECT public_key FROM paired_nodes WHERE user_id = ? AND device_did = ?")
            .bind(user_id)
            .bind(device_did)
            .fetch_optional(&mut *tx)
            .await
            .map_err(db_err)?;
    let Some(key) = key else {
        return Ok(false);
    };
    sqlx::query("DELETE FROM paired_nodes WHERE user_id = ? AND device_did = ?")
        .bind(user_id)
        .bind(device_did)
        .execute(&mut *tx)
        .await
        .map_err(db_err)?;
    drop_unreachable_drive(&mut tx, user_id, &key).await?;
    tx.commit().await.map_err(db_err)?;
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
/// what it is to this one. When this person pairs the key under two DIDs, a
/// `gateway` row answers first: within one person's rows, the narrower verb
/// wins.
pub async fn paired_posture_for_user(
    db: &Arc<SqlitePool>,
    public_key: &[u8; 32],
    user_id: &str,
) -> io::Result<Option<Option<String>>> {
    let row = sqlx::query(
        "SELECT posture FROM paired_nodes WHERE public_key = ? AND user_id = ? \
         ORDER BY (posture = 'gateway') DESC, device_did LIMIT 1",
    )
    .bind(public_key.as_slice())
    .bind(user_id)
    .fetch_optional(db.as_ref())
    .await
    .map_err(db_err)?;
    Ok(row.map(|r| r.get::<Option<String>, _>("posture")))
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
