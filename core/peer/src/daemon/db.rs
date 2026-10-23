// SPDX-License-Identifier: AGPL-3.0-or-later
//! DB access for network/pairing tables.
//!
//! Tables: `paired_nodes`, `ephemeral_sessions`, `sync_rules`, `mount_configs`,
//! created by `migrations/0002_v0_3_network.sql`; and `operator_key`, by
//! `migrations/0024_operator_key.sql`.

use kotton_wire::did::{Did, DidError};
use kotton_wire::peer::{EphemeralSession, MountConfig, PairedNode, SyncRule};
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
    // `INSERT OR REPLACE` rewrites the whole row, and callers that only know an
    // address (`peer_add`) know no posture. A posture already projected for this
    // device is kept rather than erased: erasing it turned a blind node into a
    // node of unknown posture, which no delivery would then reach.
    // The same goes for the relay the peer was last known to reserve at.
    let existing: Option<(Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT posture, relay_url FROM paired_nodes WHERE device_did = ? OR id = ? LIMIT 1",
    )
    .bind(device_did)
    .bind(id)
    .fetch_optional(db.as_ref())
    .await
    .map_err(db_err)?;
    let (existing_posture, existing_relay) = existing.unwrap_or((None, None));
    let posture: Option<String> = match posture {
        Some(p) => Some(p.to_string()),
        None => existing_posture,
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
    .execute(db.as_ref())
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

pub async fn list_paired_nodes(
    db: &Arc<SqlitePool>,
    user_id: &str,
) -> io::Result<Vec<PairedNode>> {
    let rows = sqlx::query(
        "SELECT id, device_did, public_key, paired_at, addresses, relay_url, posture \
         FROM paired_nodes WHERE user_id = ? ORDER BY paired_at DESC",
    )
    .bind(user_id)
    .fetch_all(db.as_ref())
    .await
    .map_err(db_err)?;

    let mut nodes = Vec::with_capacity(rows.len());
    for row in rows {
        let id: String = row.get("id");
        let device_did_str: String = row.get("device_did");
        let pk_bytes: Vec<u8> = row.get("public_key");
        let paired_at: i64 = row.get("paired_at");
        let addresses_json: String = row.get("addresses");

        let device_did = Did::parse(&device_did_str).map_err(did_err)?;
        let public_key: [u8; 32] = pk_bytes
            .try_into()
            .map_err(|_| io::Error::other("corrupt public_key length in paired_nodes"))?;
        let addresses: Vec<SocketAddr> = serde_json::from_str(&addresses_json).map_err(json_err)?;

        nodes.push(PairedNode {
            id,
            device_did,
            public_key,
            paired_at,
            addresses,
            relay_url: row.get::<Option<String>, _>("relay_url").filter(|u| !u.is_empty()),
            posture: row_posture(&row),
        });
    }
    Ok(nodes)
}

/// Delete a paired node. Returns `true` if a row was removed.
pub(crate) async fn delete_paired_node(
    db: &Arc<SqlitePool>,
    user_id: &str,
    node_id: &str,
) -> io::Result<bool> {
    let result = sqlx::query("DELETE FROM paired_nodes WHERE user_id = ? AND id = ?")
        .bind(user_id)
        .bind(node_id)
        .execute(db.as_ref())
        .await
        .map_err(db_err)?;
    Ok(result.rows_affected() > 0)
}



/// Delete `user_id`'s row for the device whose operational key is `public_key`.
/// Returns `true` if a row was removed.
///
/// Keyed by the key and the user, never by a name: a vault withdraws a device
/// a tenant's identity named by its key (`kvaultd::devices`), and a name is the
/// tenant's to choose and another tenant's to repeat.
pub async fn delete_paired_key(
    db: &Arc<SqlitePool>,
    user_id: &str,
    public_key: &[u8; 32],
) -> io::Result<bool> {
    let result = sqlx::query("DELETE FROM paired_nodes WHERE user_id = ? AND public_key = ?")
        .bind(user_id)
        .bind(public_key.as_slice())
        .execute(db.as_ref())
        .await
        .map_err(db_err)?;
    Ok(result.rows_affected() > 0)
}

/// Return `true` if the peer's raw Ed25519 public key is recorded in `paired_nodes` for `user_id`.
///
/// Used by `handle_peer_request` to enforce that a peer can only access data
/// belonging to users on whose behalf it was actually paired.
///
/// Keyed on `public_key` (binary) rather than `device_did` because the TLS
/// handshake presents the device's operational signing key, which is what the
/// key names; a DID recorded beside it may name another.
/// `user_id`'s paired nodes whose projected posture is `posture` (kebab-case,
/// `Posture::as_str`). Rows written before posture was projected are not
/// matched: a node whose posture is unknown is not assumed blind.
pub async fn list_paired_nodes_with_posture(
    db: &Arc<SqlitePool>,
    user_id: &str,
    posture: &str,
) -> io::Result<Vec<PairedNode>> {
    let all = list_paired_nodes(db, user_id).await?;
    let rows = sqlx::query("SELECT id FROM paired_nodes WHERE user_id = ? AND posture = ?")
        .bind(user_id)
        .bind(posture)
        .fetch_all(db.as_ref())
        .await
        .map_err(db_err)?;
    let ids: std::collections::HashSet<String> = rows.into_iter().map(|r| r.get::<String, _>("id")).collect();
    Ok(all.into_iter().filter(|n| ids.contains(&n.id)).collect())
}

/// The user a paired key belongs to, and its posture as text (`None` for rows
/// written before posture was projected here). `device_did` is unique, so a key
/// is paired to at most one user on this node.
pub async fn paired_node_for_pubkey(
    db: &Arc<SqlitePool>,
    public_key: &[u8; 32],
) -> io::Result<Option<(String, Option<String>)>> {
    let row = sqlx::query("SELECT user_id, posture FROM paired_nodes WHERE public_key = ? LIMIT 1")
        .bind(public_key.as_slice())
        .fetch_optional(db.as_ref())
        .await
        .map_err(db_err)?;
    Ok(row.map(|r| (r.get::<String, _>("user_id"), r.get::<Option<String>, _>("posture"))))
}

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
// sync_rules
// ---------------------------------------------------------------------------

pub(crate) async fn upsert_sync_rule(
    db: &Arc<SqlitePool>,
    user_id: &str,
    node_id: &str,
    path: &str,
    watch: bool,
    now: i64,
) -> io::Result<SyncRule> {
    sqlx::query(
        "INSERT INTO sync_rules (user_id, node_id, path, watch, configured_at) \
         VALUES (?, ?, ?, ?, ?) \
         ON CONFLICT(user_id, node_id, path) DO UPDATE SET \
           watch=excluded.watch, configured_at=excluded.configured_at",
    )
    .bind(user_id)
    .bind(node_id)
    .bind(path)
    .bind(watch as i32)
    .bind(now)
    .execute(db.as_ref())
    .await
    .map_err(db_err)?;

    Ok(SyncRule {
        node_id: node_id.to_owned(),
        path: path.to_owned(),
        watch,
        configured_at: now,
    })
}

pub async fn list_sync_rules(
    db: &Arc<SqlitePool>,
    user_id: &str,
) -> io::Result<Vec<SyncRule>> {
    let rows = sqlx::query(
        "SELECT node_id, path, watch, configured_at \
         FROM sync_rules WHERE user_id = ? ORDER BY configured_at DESC",
    )
    .bind(user_id)
    .fetch_all(db.as_ref())
    .await
    .map_err(db_err)?;

    Ok(rows
        .into_iter()
        .map(|row| SyncRule {
            node_id: row.get("node_id"),
            path: row.get("path"),
            watch: row.get::<i64, _>("watch") != 0,
            configured_at: row.get("configured_at"),
        })
        .collect())
}

/// Get a single paired node by its label (`id`) for a given user.
pub async fn get_paired_node_by_id(
    db: &Arc<SqlitePool>,
    user_id: &str,
    node_id: &str,
) -> io::Result<Option<PairedNode>> {
    let row_opt = sqlx::query(
        "SELECT id, device_did, public_key, paired_at, addresses, relay_url, posture \
         FROM paired_nodes WHERE user_id = ? AND id = ? LIMIT 1",
    )
    .bind(user_id)
    .bind(node_id)
    .fetch_optional(db.as_ref())
    .await
    .map_err(db_err)?;

    let Some(row) = row_opt else {
        return Ok(None);
    };

    let id: String = row.get("id");
    let device_did_str: String = row.get("device_did");
    let pk_bytes: Vec<u8> = row.get("public_key");
    let paired_at: i64 = row.get("paired_at");
    let addresses_json: String = row.get("addresses");

    let device_did = Did::parse(&device_did_str).map_err(did_err)?;
    let public_key: [u8; 32] = pk_bytes
        .try_into()
        .map_err(|_| io::Error::other("corrupt public_key length in paired_nodes"))?;
    let addresses: Vec<SocketAddr> = serde_json::from_str(&addresses_json).map_err(json_err)?;

    Ok(Some(PairedNode {
        id,
        device_did,
        public_key,
        paired_at,
        addresses,
        relay_url: row.get::<Option<String>, _>("relay_url").filter(|u| !u.is_empty()),
        posture: row_posture(&row),
    }))
}

/// Delete a sync rule. Returns `true` if a row was removed.
pub(crate) async fn delete_sync_rule(
    db: &Arc<SqlitePool>,
    user_id: &str,
    node_id: &str,
    path: &str,
) -> io::Result<bool> {
    let result =
        sqlx::query("DELETE FROM sync_rules WHERE user_id = ? AND node_id = ? AND path = ?")
            .bind(user_id)
            .bind(node_id)
            .bind(path)
            .execute(db.as_ref())
            .await
            .map_err(db_err)?;
    Ok(result.rows_affected() > 0)
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
