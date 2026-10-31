// SPDX-License-Identifier: AGPL-3.0-or-later
//! The per-user agent database (`users/{user_id}/agent.db`).
//!
//! User-scoped tables live in one database per principal, not in the
//! machine-wide `system/agent.db`, encrypted like `records.db`: SQLCipher,
//! keyed by `derive_db_key(master, kdf_labels::user_agent_db(user_id))`. This
//! module owns the whole opening path — key resolution, the per-user migration
//! set (`migrations_user/`), the lazy pool cache, and the one-time drain of
//! legacy rows from the machine-wide file, domain by domain as each domain's
//! verbs cut over.
//!
//! Domains drained from the machine-wide file: `extension_registry`.
//!
//! Like `records.db`, a user without a resolvable master secret gets an
//! **error**, never an unencrypted file. The opposite would make locking an
//! account at creation unusable: the encrypted file reopened with no key, read
//! as plaintext SQLite, and the failed pool memoised in the cache below where no
//! later unlock could repair it. Loaded is not unlocked.

use super::db_err;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqliteSynchronous};
use sqlx::SqlitePool;
use std::collections::HashMap;
use std::io;
use std::path::Path;
use std::sync::{Arc, RwLock};

use kotton_common::crypto::kdf_labels;
use kotton_crypto::{derive_db_key, derive_master_secret};
use kotton_sys::secret::SecretsStore;

/// Lazy cache of per-user pools, keyed by `user_id`. Held by `DeviceDaemon`.
///
/// Each entry is a `OnceCell` so concurrent first-contact opens of the same
/// user's database **serialize**: exactly one caller runs the migrator (sqlx's
/// `_sqlx_migrations` insert is not concurrency-safe on one file) and everyone
/// else awaits the same pool. A failed open leaves the cell empty, so the next
/// call retries — e.g. after a login makes the key resolvable.
pub type UserDbMap = Arc<RwLock<HashMap<String, UserDbSlot>>>;

/// A user's slot in the pool cache.
///
/// The `Closing` state exists because eviction alone cannot win a race it does
/// not control. Logout closes the pool and then deletes `users/{id}/`, but
/// anything that calls [`user_agent_db`] in between — the sync engine's
/// background pass is the live example — would find no entry, take that to mean
/// "first contact", and **re-open the very file being deleted**. Closing the
/// pool harder does not help; the opener has to be told to stop. So teardown
/// leaves a marker rather than a hole, and [`release`] removes it once logout
/// has finished with the directory.
#[derive(Clone)]
pub enum UserDbSlot {
    /// Open, or opening: the shared cell every concurrent caller awaits.
    Live(Arc<tokio::sync::OnceCell<Arc<SqlitePool>>>),
    /// Being torn down. Opens are refused until logout releases it.
    Closing,
}

/// The per-user schema. Versioned separately from the machine-wide
/// `migrations/` set — this is a different database with its own history.
static USER_MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations_user");

/// Resolve a user's master secret from the OS keychain.
///
/// Prefers the random operational `master_secret`; falls back to
/// the legacy `seed32`-derived master for pre-cutover accounts. `Ok(None)` when
/// the store answered that it holds neither — the caller decides what that means
/// for its domain. A store that could not be read is an error, and the fallback
/// is never taken for it: an unreadable `master_secret` falling through to the
/// derivation would key `agent.db` and the event log's HMAC chain under a key
/// derived from another root.
pub(crate) fn resolve_master(secrets: &dyn SecretsStore, user_id: &str) -> io::Result<Option<[u8; 32]>> {
    fn decode32(h: String) -> Option<[u8; 32]> {
        hex::decode(h).ok().and_then(|b| b.try_into().ok())
    }
    let read = |label: String| {
        secrets
            .get_secret(&label)
            .map_err(|e| io::Error::other(format!("could not read {label} from the secrets store: {e}")))
    };
    if let Some(master) = read(kdf_labels::master_secret_keychain_key(user_id))?.and_then(decode32) {
        return Ok(Some(master));
    }
    Ok(read(kdf_labels::seed32_keychain_key(user_id))?
        .and_then(decode32)
        .map(|seed32| derive_master_secret(&seed32)))
}

/// Fetch (or lazily open) the per-user agent database for `user_id`.
///
/// `schema_registry` is hydrated from this user's persisted schemas on the open
/// that creates the pool, and not on any later call. The `OnceCell` below is
/// already the daemon's "exactly once per user" mechanism, so the loading of
/// durable registrations rides it rather than keeping a second set of
/// bookkeeping that could drift from it — and, being per-daemon rather than
/// per-process, several daemons in one test process each hydrate their own
/// registry.
pub(crate) async fn user_agent_db(
    map: &UserDbMap,
    base: &Path,
    secrets: &dyn SecretsStore,
    user_id: &str,
    schema_registry: &RwLock<kotton_record::registry::SchemaRegistry>,
) -> io::Result<Arc<SqlitePool>> {
    // A caller with no principal must resolve one *before* reaching here —
    // an empty id would silently mint a `users//agent.db` nobody owns.
    if user_id.is_empty() {
        return Err(io::Error::other(
            "user_agent_db requires a user id; empty means no principal was resolved",
        ));
    }
    let cell = {
        let mut guard = map.write().unwrap();
        match guard
            .entry(user_id.to_string())
            .or_insert_with(|| UserDbSlot::Live(Arc::new(tokio::sync::OnceCell::new())))
        {
            UserDbSlot::Live(cell) => Arc::clone(cell),
            // Refusing here is what makes logout's directory delete safe: a
            // background pass that asks for this user mid-teardown is told no,
            // rather than silently re-opening the file being removed.
            UserDbSlot::Closing => {
                return Err(io::Error::other(format!(
                    "user '{user_id}' is being logged out; their database is closed"
                )))
            }
        }
    };

    let pool = cell
        .get_or_try_init(|| async {
            open_user_agent_db(base, secrets, user_id, schema_registry)
                .await
                .map(Arc::new)
        })
        .await
        .cloned()?;

    // Re-check the slot, because the guard above is not sufficient on its own.
    // A caller can be holding this `cell` from before an eviction, and an
    // `OnceCell` whose initializer returned `Err` is *empty again* — which is
    // exactly what eviction leaves behind when it evicts a never-opened user.
    // Such a caller would then run its own initializer and re-open the file,
    // into a cell no longer reachable from the map: open, orphaned, and closed
    // by nobody until the process exits. That is a directory delete that fails
    // for reasons no amount of closing the *cached* pool can fix.
    //
    // Identity, not just presence: the slot may also have been released and
    // re-opened by someone else, in which case this pool is equally orphaned.
    let still_ours = match map.read().unwrap().get(user_id) {
        Some(UserDbSlot::Live(current)) => Arc::ptr_eq(current, &cell),
        _ => false,
    };
    if !still_ours {
        super::close_pool(&pool).await;
        return Err(io::Error::other(format!(
            "user '{user_id}' database was closed while it was being opened"
        )));
    }

    Ok(pool)
}

/// The agent databases this daemon already holds open, read and never written:
/// a view of a [`UserDbMap`] whose one method answers whether `user_id`'s
/// database is open, and returns it if so.
///
/// It never opens, creates or migrates a database and never adds or removes a
/// slot — not by its method's restraint but because it has no method that
/// could, and its map is private to this module. The daemon opens a person's
/// database when it takes them up (boot, sign-in, unlock: [`user_agent_db`]);
/// this answers from what that left. A holder of this view — the peer path's
/// guest lookup (kotton #262) — holds no base directory or keychain to open one
/// with, and no way to write the map.
#[derive(Clone)]
pub(crate) struct OpenAgentDbs(UserDbMap);

impl OpenAgentDbs {
    /// A read-only view of `map`.
    pub(crate) fn of(map: &UserDbMap) -> Self {
        Self(Arc::clone(map))
    }

    /// `user_id`'s agent database if it is open now; `None` otherwise.
    pub(crate) fn get(&self, user_id: &crate::device_users::UserId) -> Option<Arc<SqlitePool>> {
        match self.0.read().unwrap().get(user_id.as_str()) {
            Some(UserDbSlot::Live(cell)) => cell.get().cloned(),
            _ => None,
        }
    }
}

/// Open (or create) `users/{user_id}/agent.db`, run the per-user migrations,
/// and drain legacy rows from the machine-wide database on first contact.
async fn open_user_agent_db(
    base: &Path,
    secrets: &dyn SecretsStore,
    user_id: &str,
    schema_registry: &RwLock<kotton_record::registry::SchemaRegistry>,
) -> io::Result<SqlitePool> {
    let path = base.join("users").join(user_id).join("agent.db");
    if let Some(parent) = path.parent() {
        kotton_common::fs::create_dir_all_owner_only(parent)
            .map_err(|e| io::Error::other(format!("cannot create user db dir: {e}")))?;
    }

    // No key is a refusal, never a plaintext database — see `records.db`. A
    // locked account has keys that are deliberately unresolvable,
    // and opening its encrypted file with no key both mis-reads it and memoises
    // the broken pool below, where a later unlock cannot reach it.
    // A store that could not be read is `Locked` too, by its own cause: a locked
    // keychain is transient, so the window offers the unlock — and it is not a
    // database that will not open, which a credential could never fix.
    let db_key: [u8; 32] = resolve_master(secrets, user_id)
        .map_err(|e| {
            io::Error::other(kotton_record::open::Locked {
                user_id: user_id.to_string(),
                what: "agent.db",
                by: kotton_record::open::LockedBy::UnreadableStore(e.to_string()),
            })
        })?
        .map(|m| derive_db_key(&m, &kdf_labels::user_agent_db(user_id)))
        .ok_or_else(|| {
            // Typed, not formatted: the compositor has to tell *locked* from *missing* to
            // decide whether offering a credential prompt would be honest. `Display`
            // renders the plain sentence.
            io::Error::other(kotton_record::open::Locked {
                user_id: user_id.to_string(),
                what: "agent.db",
                by: kotton_record::open::LockedBy::NoKey,
            })
        })?;

    let pool = open_at(&path, Some(&db_key)).await?;
    USER_MIGRATOR
        .run(&pool)
        .await
        .map_err(|e| io::Error::other(format!("user agent.db migration failed: {e}")))?;

    let owner_did = kotton_identity::owner_did_for(user_id, secrets);
    drain_legacy_tables(
        &pool,
        &base.join("system").join("agent.db"),
        user_id,
        owner_did.as_deref(),
    )
    .await?;

    hydrate_schema_registry(&pool, user_id, schema_registry).await;

    // Seed the default shell role, after the drain so a user's own override
    // wins. Lives on the open path rather than in a boot pass so a user
    // created after boot gets it the moment their database first opens.
    sqlx::query(
        "INSERT OR IGNORE INTO app_roles (role, app_id) VALUES ('shell', 'sh.kotton.shell')",
    )
    .execute(&pool)
    .await
    .map_err(db_err)?;

    Ok(pool)
}

/// Open a pool at `path`, keyed when `key` is `Some`.
///
/// sqlx orders the `key` pragma ahead of every other statement on the
/// connection (its SQLCipher special case), which is the invariant SQLCipher
/// requires; the wrong-key test below pins that this is real encryption and
/// not a silently ignored pragma.
///
/// WAL, as the record crate's pool (`kotton_record::open_sqlite`) runs, and FULL,
/// as it does not. This is a
/// pool, so another connection is often mid-read; under the rollback journal a
/// commit waits for every such read to end, and past the busy timeout it fails.
/// Under WAL a read keeps the snapshot it started with and a commit does not wait
/// for it: what a write answers is visible to every read that starts after it.
/// FULL fsyncs the WAL at each commit, so a commit that answered survives power
/// loss, as it did under the rollback journal; NORMAL, the record store's
/// choice, would trade that away and is not this file's to trade.
async fn open_at(path: &Path, key: Option<&[u8; 32]>) -> io::Result<SqlitePool> {
    let mut opts = SqliteConnectOptions::new()
        .filename(path)
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal)
        .synchronous(SqliteSynchronous::Full);
    if let Some(key) = key {
        opts = opts.pragma("key", format!("\"x'{}'\"", hex::encode(key)));
    }
    SqlitePool::connect_with(opts).await.map_err(db_err)
}

/// How a drained table's legacy rows are scoped to the opening user.
enum DrainScope {
    /// No user column: rows move whole into the first per-user database opened
    /// on the machine (sole-user devices are today's fleet).
    Whole,
    /// Rows whose named column equals the user's identity DID
    /// ([`kotton_identity::owner_did_for`]); skipped when the identity key is unresolvable —
    /// the first-contact guard lets a later open drain them.
    OwnerDid(&'static str),
    /// Rows whose named column equals the `user_id`.
    UserId(&'static str),
    /// Child rows whose key appears in the already-drained parent table on
    /// the user side — order entries parent-first.
    ParentIn {
        parent: &'static str,
        key: &'static str,
    },
}

/// Every table that has moved (or moves) from the machine-wide `agent.db`
/// into the per-user database, with its column list and drain scope. Column
/// lists are explicit so the copy is column-order-independent; each new slice
/// appends here.
const DRAINED_TABLES: &[(&str, &str, DrainScope)] = &[
    // 3b-i
    (
        "extension_registry",
        "extension_id, name, version, class, description, wasm_path, content_hash, \
         publisher_did, network_json, credential_slots, installed_at",
        DrainScope::Whole,
    ),
    // 3b-ii — the app cluster
    (
        "app_registry",
        "app_id, name, version, capabilities, wasm_path, installed_at, wasm_hash, \
         bundle_path, dev",
        DrainScope::Whole,
    ),
    (
        "handler_registry",
        "app_id, nsid, is_default, registered_at",
        DrainScope::Whole,
    ),
    ("app_roles", "role, app_id", DrainScope::Whole),
    (
        "schema_grants",
        "app_id, nsid, can_read, can_write, can_register, record_quota, byte_quota, \
         record_count, byte_count, granted_at",
        DrainScope::Whole,
    ),
    // 3b-iii — the grant cluster
    (
        "app_grant_envelopes",
        "id, app_id, envelope_json, stored_at",
        DrainScope::Whole,
    ),
    // The caller's own revocations only; org-issued revocations live in the
    // machine-wide list deliberately (the org-to-member channel) and never drain.
    (
        "revocation_list",
        "envelope_id, revoked_at",
        DrainScope::Whole,
    ),
    ("trusted_issuers", "did, added_at", DrainScope::Whole),
    (
        "imported_grant_envelopes",
        "id, issuer_did, subject_did, envelope_json, imported_at",
        DrainScope::Whole,
    ),
    // 3b-iv — orgs and FROST (owner/participant bookkeeping; parent-first)
    (
        "org_identities",
        "org_did, name, owner_did, created_at",
        DrainScope::OwnerDid("owner_did"),
    ),
    (
        "org_members",
        "org_did, member_did, envelope_id, issued_at",
        DrainScope::ParentIn {
            parent: "org_identities",
            key: "org_did",
        },
    ),
    (
        "frost_orgs",
        "org_did, name, owner_did, threshold, total, pubkey_package_hex, created_at",
        DrainScope::OwnerDid("owner_did"),
    ),
    // Per-device participant material with no user column (PK org_did already
    // assumes one local participant); moves whole, like the app tables.
    (
        "frost_key_packages",
        "org_did, key_package_hex, participant_idx, participant_id_hex",
        DrainScope::Whole,
    ),
    (
        "frost_signing_sessions",
        "session_id, org_did, user_id, member_did, caps_json, ttl_secs, node_did, \
         message_hex, nonces_hex, commitment_hex, participant_id_hex, state, created_at",
        DrainScope::UserId("user_id"),
    ),
    (
        "frost_signing_contributions",
        "session_id, participant_id_hex, commitment_hex, share_hex",
        DrainScope::ParentIn {
            parent: "frost_signing_sessions",
            key: "session_id",
        },
    ),
    // 3b-v — the network user tables (user_id columns all along)
    // `sync_rules` is not drained: a rule named a paired node, and a rule now
    // names a drive (`0012_drive_rules.sql`), so a legacy rule has nowhere to
    // go.
    (
        "mount_configs",
        "id, user_id, node_id, remote_path, local_path, cache_budget_bytes, pins, mounted_at",
        DrainScope::UserId("user_id"),
    ),
    (
        "ephemeral_sessions",
        "id, user_id, guest_did, guest_pubkey, grant_json, issued_at, revoked",
        DrainScope::UserId("user_id"),
    ),
];

/// Close and evict a user's pool from the cache.
///
/// Must run **before** anything deletes `users/{user_id}/` — Windows refuses
/// to remove a directory whose `agent.db` a pool still holds open. A later
/// verb for the same user simply re-opens (fresh cell, first-contact rules).
///
/// An **in-flight** open is awaited, not skipped: `cell.get()` returns `None`
/// while an initializer runs, and evicting past it would orphan the pool that
/// initializer is about to produce — open, uncached, and closed only by the
/// async drop reaper, long after a directory delete has already failed.
/// `get_or_try_init` joins the in-flight init when there is one; the fallback
/// closure only runs (and yields nothing to close) if no init ever started.
pub(crate) async fn evict(map: &UserDbMap, user_id: &str) {
    // Mark first, close second. The marker is what stops anyone re-opening the
    // file while the close and the directory delete are still in progress;
    // removing the entry instead would leave a hole that reads as first
    // contact, and the next background pass would open it straight back up.
    let previous = map
        .write()
        .unwrap()
        .insert(user_id.to_string(), UserDbSlot::Closing);

    if let Some(UserDbSlot::Live(cell)) = previous {
        let joined = cell
            .get_or_try_init(|| async {
                Err::<Arc<SqlitePool>, io::Error>(io::Error::other("evicted before first open"))
            })
            .await;
        if let Ok(pool) = joined {
            // Not `pool.close()`: that can return with a connection still out
            // (see `close_pool`), and "closed" is what the directory delete and
            // the process's exit both rely on.
            super::close_pool(pool).await;
        }
    }
}

/// Drop a user's `Closing` marker once logout has finished with their files.
///
/// Called after the directory is gone, so the name is free again: creating or
/// logging in as the same `user_id` later opens a fresh database under
/// first-contact rules. Leaving the marker in place would make that user
/// permanently unopenable until the daemon restarted.
pub(crate) fn release(map: &UserDbMap, user_id: &str) {
    let mut guard = map.write().unwrap();
    if matches!(guard.get(user_id), Some(UserDbSlot::Closing)) {
        guard.remove(user_id);
    }
}

/// Put this user's durable schema registrations back into the in-memory registry.
///
/// The registry is rebuilt from the sealed core set at every start, so without
/// this a restart leaves the user's records on disk and unreadable —
/// `record_cmds::query` refuses an NSID it does not know, and replicated rows
/// under a custom schema are skipped.
///
/// **Never fails the open.** A user whose stored definitions cannot be read is
/// no worse off than before this existed: core schemas still work and their
/// records are still on disk. Refusing to open the database would take away the
/// rest of their data to punish one unreadable row.
async fn hydrate_schema_registry(
    pool: &SqlitePool,
    user_id: &str,
    schema_registry: &RwLock<kotton_record::registry::SchemaRegistry>,
) {
    let defs = match kotton_record::daemon::db::app_schemas_db::load_all(pool).await {
        Ok(defs) => defs,
        Err(e) => {
            tracing::warn!(user = %user_id, error = %e, "could not load persisted schemas");
            return;
        }
    };
    if defs.is_empty() {
        return;
    }

    let count = defs.len();
    let dropped = schema_registry
        .write()
        .unwrap()
        .load_persisted(defs, user_id);
    for nsid in &dropped {
        tracing::warn!(
            user = %user_id,
            nsid = %nsid,
            "persisted schema dropped on load: its `extends` parent is not registered"
        );
    }
    tracing::debug!(
        user = %user_id,
        loaded = count - dropped.len(),
        dropped = dropped.len(),
        "restored persisted schema registrations"
    );
}

/// One-time move of legacy rows out of the machine-wide `agent.db`.
///
/// Each table's [`DrainScope`] decides which rows are the opening user's;
/// scoped drains delete only what they copied, so other users' rows wait for
/// their own daemons. Each table drains only while its per-user side is empty;
/// a crash between copy and delete resolves as "already imported" on the next
/// boot, and nothing reads the legacy tables any more.
///
/// Mechanism: the plaintext machine database is `ATTACH`ed to one connection
/// of the (possibly SQLCipher-keyed) user pool with `KEY ''`, so each copy is
/// a single `INSERT ... SELECT` and the whole family of slices shares one
/// code path.
async fn drain_legacy_tables(
    user_db: &SqlitePool,
    machine_db_path: &Path,
    user_id: &str,
    owner_did: Option<&str>,
) -> io::Result<()> {
    if !machine_db_path.exists() {
        return Ok(());
    }
    let mut conn = user_db.acquire().await.map_err(db_err)?;

    let path_sql = machine_db_path.to_string_lossy().replace('\'', "''");
    sqlx::query(&format!("ATTACH DATABASE '{path_sql}' AS legacy KEY ''"))
        .execute(&mut *conn)
        .await
        .map_err(db_err)?;

    let result = drain_each(&mut conn, user_id, owner_did).await;
    // Best-effort: the pool may reuse this connection for ordinary queries.
    let _ = sqlx::query("DETACH DATABASE legacy")
        .execute(&mut *conn)
        .await;
    result
}

async fn drain_each(
    conn: &mut sqlx::SqliteConnection,
    user_id: &str,
    owner_did: Option<&str>,
) -> io::Result<()> {
    for (table, cols, scope) in DRAINED_TABLES {
        // A legacy file that predates the table (an install that never reached
        // that migration) simply has nothing to drain.
        let (present,): (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM legacy.sqlite_master WHERE type = 'table' AND name = ?",
        )
        .bind(table)
        .fetch_one(&mut *conn)
        .await
        .map_err(db_err)?;
        if present == 0 {
            continue;
        }

        let (mine,): (i64,) = sqlx::query_as(&format!("SELECT COUNT(*) FROM {table}"))
            .fetch_one(&mut *conn)
            .await
            .map_err(db_err)?;
        if mine > 0 {
            continue;
        }

        // (predicate SQL, bound value) — the same predicate copies and deletes,
        // so a scoped drain touches exactly the rows it claimed.
        let (predicate, bind_value): (String, Option<&str>) = match scope {
            DrainScope::Whole => (String::new(), None),
            DrainScope::OwnerDid(col) => match owner_did {
                Some(did) => (format!(" WHERE {col} = ?"), Some(did)),
                // Identity key unresolvable: leave the rows for a later open —
                // the first-contact guard above keeps this retryable.
                None => continue,
            },
            DrainScope::UserId(col) => (format!(" WHERE {col} = ?"), Some(user_id)),
            DrainScope::ParentIn { parent, key } => (
                format!(" WHERE {key} IN (SELECT {key} FROM main.{parent})"),
                None,
            ),
        };

        let copy_sql = format!(
            "INSERT OR REPLACE INTO {table} ({cols}) SELECT {cols} FROM legacy.{table}{predicate}"
        );
        let delete_sql = format!("DELETE FROM legacy.{table}{predicate}");

        let mut copy = sqlx::query(&copy_sql);
        if let Some(v) = bind_value {
            copy = copy.bind(v);
        }
        let copied = copy.execute(&mut *conn).await.map_err(db_err)?;

        let mut delete = sqlx::query(&delete_sql);
        if let Some(v) = bind_value {
            delete = delete.bind(v);
        }
        delete.execute(&mut *conn).await.map_err(db_err)?;

        if copied.rows_affected() > 0 {
            tracing::info!(
                table,
                rows = copied.rows_affected(),
                "drained from agent.db into the user's agent.db (RFC-0063 stage 3b)"
            );
        }
    }
    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// **A master secret the store cannot read is an error, never the `seed32`
    /// derivation.** Taken for absent, the read would fall through to the
    /// legacy fallback and key `agent.db` and the event log's HMAC chain with a
    /// key derived from another root.
    #[test]
    fn an_unreadable_master_secret_is_an_error_not_the_seed_derivation() {
        struct MasterUnreadable(kotton_secret::MemorySecrets);
        impl SecretsStore for MasterUnreadable {
            fn get_secret(&self, key: &str) -> kotton_sys::secret::SecretsResult<Option<String>> {
                if key == kdf_labels::master_secret_keychain_key("u") {
                    return Err(kotton_sys::secret::SecretsError::Storage("the keychain did not answer".into()));
                }
                self.0.get_secret(key)
            }
            fn set_secret(&self, key: &str, value: &str) -> kotton_sys::secret::SecretsResult<()> {
                self.0.set_secret(key, value)
            }
            fn delete_secret(&self, key: &str) -> kotton_sys::secret::SecretsResult<()> {
                self.0.delete_secret(key)
            }
        }
        let inner = kotton_secret::MemorySecrets::new();
        inner.set_secret(&kdf_labels::seed32_keychain_key("u"), &hex::encode([7u8; 32])).unwrap();
        let got = format!("{:?}", resolve_master(&MasterUnreadable(inner), "u"));
        assert!(got.contains("the keychain did not answer"), "the read's error is returned: {got}");
    }

    /// A legacy machine-wide `agent.db` on disk, carrying the drained tables'
    /// legacy DDL (base migrations plus their ALTERs, as an upgrade would).
    async fn machine_db_at(path: &Path) -> SqlitePool {
        let pool = open_at(path, None).await.unwrap();
        for sql in [
            include_str!("../../../device/migrations/0020_extension_registry.sql"),
            include_str!("../../../device/migrations/0005_v0_5_handler_registry.sql"),
            include_str!("../../../device/migrations/0006_v0_6_app_registry.sql"),
            include_str!("../../../device/migrations/0007_v0_7_app_wasm_hash.sql"),
            include_str!("../../../device/migrations/0016_bundle_path.sql"),
            include_str!("../../../device/migrations/0017_app_roles.sql"),
            include_str!("../../../device/migrations/0018_schema_grants.sql"),
            include_str!("../../../device/migrations/0013_org_identities.sql"),
            include_str!("../../../device/migrations/0014_frost_sessions.sql"),
        ] {
            sqlx::raw_sql(sql).execute(&pool).await.unwrap();
        }
        pool
    }

    async fn insert_dummy_extension(pool: &SqlitePool, id: &str) {
        sqlx::query(
            "INSERT INTO extension_registry \
             (extension_id, name, version, class, description, wasm_path, content_hash, installed_at) \
             VALUES (?, 'X', '0.1.0', 'fetcher', '', '/x.wasm', ?, 1)",
        )
        .bind(id)
        .bind("a".repeat(64))
        .execute(pool)
        .await
        .unwrap();
    }

    async fn insert_dummy(pool: &SqlitePool, id: &str) {
        insert_dummy_extension(pool, id).await;
    }

    // ── schema persistence: a custom schema survives a restart ──────────

    /// A per-user database with the user migration set applied — what
    /// `open_user_agent_db` produces, without the key resolution around it.
    async fn user_db_at(path: &Path) -> SqlitePool {
        let pool = open_at(path, None).await.unwrap();
        USER_MIGRATOR.run(&pool).await.unwrap();
        pool
    }

    fn a_schema(nsid: &str) -> kotton_schemas::definition::SchemaDefinition {
        use kotton_schemas::field::{FieldType, SchemaField};
        kotton_schemas::definition::SchemaDefinition {
            nsid: kotton_schemas::nsid::Nsid::new(nsid).unwrap(),
            version: 1,
            fields: vec![SchemaField {
                name: "content".to_owned(),
                field_type: FieldType::String,
                nullable: false,
                default: None,
            }],
            forked_from: None,
            description: Some("persisted".to_owned()),
        }
    }

    #[tokio::test]
    async fn a_stored_schema_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let pool = user_db_at(&dir.path().join("agent.db")).await;

        kotton_record::daemon::db::app_schemas_db::upsert(&pool, &a_schema("com.test.kept"))
            .await
            .unwrap();
        let loaded = kotton_record::daemon::db::app_schemas_db::load_all(&pool)
            .await
            .unwrap();

        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].nsid.as_str(), "com.test.kept");
        assert_eq!(loaded[0].description.as_deref(), Some("persisted"));
    }

    #[tokio::test]
    async fn re_registering_a_higher_version_replaces_the_stored_row() {
        let dir = tempfile::tempdir().unwrap();
        let pool = user_db_at(&dir.path().join("agent.db")).await;

        kotton_record::daemon::db::app_schemas_db::upsert(&pool, &a_schema("com.test.bumped"))
            .await
            .unwrap();
        let mut v2 = a_schema("com.test.bumped");
        v2.version = 2;
        kotton_record::daemon::db::app_schemas_db::upsert(&pool, &v2)
            .await
            .unwrap();

        let loaded = kotton_record::daemon::db::app_schemas_db::load_all(&pool)
            .await
            .unwrap();
        assert_eq!(
            loaded.len(),
            1,
            "an upgrade replaces rather than duplicates"
        );
        assert_eq!(loaded[0].version, 2);
    }

    /// The whole point: a **fresh registry** meeting an **existing database** is
    /// what a restart is. Before this existed, the registry came up holding only
    /// core schemas and the user's records answered "unknown schema".
    #[tokio::test]
    async fn a_fresh_registry_recovers_schemas_from_an_existing_database() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.db");

        // Session one: register, and persist what the registry accepted.
        {
            let pool = user_db_at(&path).await;
            kotton_record::daemon::db::app_schemas_db::upsert(
                &pool,
                &a_schema("com.test.survivor"),
            )
            .await
            .unwrap();
            pool.close().await;
        }

        // Session two: a registry built from nothing but the sealed core set.
        let registry = RwLock::new(kotton_record::registry::SchemaRegistry::new());
        let nsid = kotton_schemas::nsid::Nsid::new("com.test.survivor").unwrap();
        assert!(
            registry.read().unwrap().get(&nsid).is_none(),
            "a new registry starts with core schemas only"
        );

        let pool = user_db_at(&path).await;
        hydrate_schema_registry(&pool, "alice", &registry).await;

        let guard = registry.read().unwrap();
        assert!(
            guard.get(&nsid).is_some(),
            "the registration must come back without the app re-registering"
        );
        assert!(
            guard.get_for("alice", &nsid).is_some(),
            "and it must come back owned by the user who registered it"
        );
    }

    #[tokio::test]
    async fn hydrating_an_empty_database_is_a_no_op() {
        let dir = tempfile::tempdir().unwrap();
        let pool = user_db_at(&dir.path().join("agent.db")).await;
        let registry = RwLock::new(kotton_record::registry::SchemaRegistry::new());
        let before = registry.read().unwrap().len();

        hydrate_schema_registry(&pool, "alice", &registry).await;

        assert_eq!(registry.read().unwrap().len(), before);
    }

    async fn count_in(pool: &SqlitePool, table: &str) -> i64 {
        sqlx::query_as::<_, (i64,)>(&format!("SELECT COUNT(*) FROM {table}"))
            .fetch_one(pool)
            .await
            .unwrap()
            .0
    }

    async fn count(pool: &SqlitePool) -> i64 {
        count_in(pool, "extension_registry").await
    }

    /// The encryption is real: a file created under one key refuses to open
    /// under another — not a silently ignored pragma.
    #[tokio::test]
    async fn wrong_key_fails_to_open() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.db");
        let key_a = [7u8; 32];
        let key_b = [9u8; 32];

        let pool = open_at(&path, Some(&key_a)).await.unwrap();
        USER_MIGRATOR.run(&pool).await.unwrap();
        insert_dummy(&pool, "sh.kotton.a").await;
        pool.close().await;

        // Refused at the open itself: setting WAL reads the file's header on
        // connect, which a wrong key cannot decrypt (SQLITE_NOTADB). Under the
        // rollback journal `open_at` ran before, the open succeeded and the
        // first read failed.
        let wrong = open_at(&path, Some(&key_b)).await;
        let err = wrong.expect_err("a wrong key must not open an encrypted db");
        assert!(
            err.to_string().contains("file is not a database"),
            "refused for the key, not something else: {err}"
        );
    }

    /// The same key reopens the same data.
    #[tokio::test]
    async fn right_key_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.db");
        let key = [7u8; 32];

        let pool = open_at(&path, Some(&key)).await.unwrap();
        USER_MIGRATOR.run(&pool).await.unwrap();
        insert_dummy(&pool, "sh.kotton.a").await;
        pool.close().await;

        let again = open_at(&path, Some(&key)).await.unwrap();
        assert_eq!(count(&again).await, 1);
    }

    /// Legacy rows drain once: into the user db, out of the machine db, and a
    /// populated user db is never overwritten by a later boot. Runs across the
    /// whole drained-table family, into an encrypted user db — the attach path
    /// (plaintext legacy attached to a keyed connection) is exactly production.
    #[tokio::test]
    async fn legacy_rows_drain_once() {
        let dir = tempfile::tempdir().unwrap();
        let machine_path = dir.path().join("system").join("agent.db");
        std::fs::create_dir_all(machine_path.parent().unwrap()).unwrap();
        let machine = machine_db_at(&machine_path).await;
        insert_dummy(&machine, "sh.kotton.legacy").await;
        sqlx::raw_sql(
            "INSERT INTO app_registry (app_id, name, version, wasm_path, installed_at) \
             VALUES ('sh.kotton.notes', 'Notes', '1.0', '/n.wasm', '2026-01-01'); \
             INSERT INTO app_roles (role, app_id) VALUES ('shell', 'sh.kotton.shell'); \
             INSERT INTO handler_registry (app_id, nsid) VALUES ('sh.kotton.notes', 'sh.kotton.note'); \
             INSERT INTO schema_grants (app_id, nsid, can_read) VALUES ('sh.kotton.notes', 'sh.kotton.note', 1);",
        )
        .execute(&machine)
        .await
        .unwrap();

        let key = [5u8; 32];
        let user = open_at(&dir.path().join("agent.db"), Some(&key))
            .await
            .unwrap();
        USER_MIGRATOR.run(&user).await.unwrap();

        drain_legacy_tables(&user, &machine_path, "owner", None)
            .await
            .unwrap();
        for table in [
            "extension_registry",
            "app_registry",
            "app_roles",
            "handler_registry",
            "schema_grants",
        ] {
            assert_eq!(count_in(&user, table).await, 1, "{table}: row moved in");
            assert_eq!(count_in(&machine, table).await, 0, "{table}: row moved out");
        }

        // A second drain against a machine db that has grown a row again (e.g.
        // an old binary wrote one) must not clobber the user's table.
        insert_dummy(&machine, "sh.kotton.stale").await;
        drain_legacy_tables(&user, &machine_path, "owner", None)
            .await
            .unwrap();
        assert_eq!(count(&user).await, 1, "populated user db is left alone");
    }

    /// The restart sequence integration tests exercise: an encrypted file, a
    /// failed key-less open attempt (pre-login boot), then a correctly keyed
    /// open. The failed attempt must not poison the file.
    #[tokio::test]
    async fn failed_keyless_open_does_not_poison_an_encrypted_db() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.db");
        let key = [3u8; 32];

        let pool = open_at(&path, Some(&key)).await.unwrap();
        USER_MIGRATOR.run(&pool).await.unwrap();
        insert_dummy(&pool, "sh.kotton.a").await;
        pool.close().await;

        // Pre-login boot: no key resolvable — the open + migrate attempt fails.
        if let Ok(wrong) = open_at(&path, None).await {
            let _ = USER_MIGRATOR.run(&wrong).await;
            wrong.close().await;
        }

        // Post-login: the correct key must still open the same data.
        let again = open_at(&path, Some(&key)).await.unwrap();
        USER_MIGRATOR.run(&again).await.unwrap();
        assert_eq!(count(&again).await, 1);
    }

    /// A scoped drain takes exactly the opener's rows — the other user's orgs,
    /// members, and signing sessions stay in the legacy file for their own
    /// daemon's first contact.
    #[tokio::test]
    async fn scoped_drains_take_only_the_openers_rows() {
        let dir = tempfile::tempdir().unwrap();
        let machine_path = dir.path().join("agent.db");
        let machine = machine_db_at(&machine_path).await;
        sqlx::raw_sql(
            "INSERT INTO org_identities (org_did, name, owner_did, created_at) VALUES \
               ('did:key:orgA', 'A', 'did:key:alice', 1), \
               ('did:key:orgB', 'B', 'did:key:bob', 1); \
             INSERT INTO org_members (org_did, member_did, envelope_id, issued_at) VALUES \
               ('did:key:orgA', 'did:key:m1', 'env-a', 1), \
               ('did:key:orgB', 'did:key:m2', 'env-b', 1); \
             INSERT INTO frost_signing_sessions \
               (session_id, org_did, user_id, member_did, caps_json, message_hex, \
                nonces_hex, commitment_hex, participant_id_hex, created_at) VALUES \
               ('s-alice', 'did:key:orgA', 'alice', 'did:key:m1', '[]', '00', '00', '00', '01', 1), \
               ('s-bob',   'did:key:orgB', 'bob',   'did:key:m2', '[]', '00', '00', '00', '01', 1); \
             INSERT INTO frost_signing_contributions \
               (session_id, participant_id_hex, commitment_hex, share_hex) VALUES \
               ('s-alice', '02', '00', '00'), \
               ('s-bob',   '02', '00', '00');",
        )
        .execute(&machine)
        .await
        .unwrap();

        let user = open_at(&dir.path().join("alice.db"), None).await.unwrap();
        USER_MIGRATOR.run(&user).await.unwrap();
        drain_legacy_tables(&user, &machine_path, "alice", Some("did:key:alice"))
            .await
            .unwrap();

        for (table, want_user, want_legacy) in [
            ("org_identities", 1, 1),
            ("org_members", 1, 1),
            ("frost_signing_sessions", 1, 1),
            ("frost_signing_contributions", 1, 1),
        ] {
            assert_eq!(
                count_in(&user, table).await,
                want_user,
                "{table}: alice's row"
            );
            assert_eq!(
                count_in(&machine, table).await,
                want_legacy,
                "{table}: bob's row stays for his own drain"
            );
        }
        // And the rows that moved are actually alice's.
        let (owner,): (String,) = sqlx::query_as("SELECT owner_did FROM org_identities")
            .fetch_one(&user)
            .await
            .unwrap();
        assert_eq!(owner, "did:key:alice");
    }

    /// A legacy file that predates a drained table (an install that never ran
    /// that migration) drains what it has and skips the rest.
    #[tokio::test]
    async fn missing_legacy_tables_are_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let machine_path = dir.path().join("agent.db");
        let machine = open_at(&machine_path, None).await.unwrap();
        sqlx::raw_sql(include_str!(
            "../../../device/migrations/0020_extension_registry.sql"
        ))
        .execute(&machine)
        .await
        .unwrap();
        insert_dummy(&machine, "sh.kotton.only").await;

        let user = open_at(&dir.path().join("user.db"), None).await.unwrap();
        USER_MIGRATOR.run(&user).await.unwrap();

        drain_legacy_tables(&user, &machine_path, "owner", None)
            .await
            .unwrap();
        assert_eq!(count(&user).await, 1);
        assert_eq!(count_in(&user, "app_registry").await, 0);
    }

    /// `evict` returns only once every connection the pool opened is closed —
    /// including one a caller still holds mid-query when eviction starts.
    ///
    /// That caller is the sync engine's background pass, seen in four of five cores
    /// of a suite run that aborted at exit on a corrupted heap: a pass began
    /// `list_sync_rules` on a user's keyed `agent.db`, shutdown evicted the pool,
    /// `close()` returned with the connection still out, the runtime then dropped
    /// the pass mid-query, and the connection's detached worker was still inside
    /// SQLCipher's HMAC when `exit()` ran libcrypto's `OPENSSL_cleanup` under it.
    ///
    /// The idle connections are the part that makes it real. sqlx-core 0.8.0's
    /// `close()` gives back a semaphore permit for each idle connection it closes
    /// that `release()` already gave back when it went idle, so with any idle
    /// connection closed its final `acquire(max_connections)` succeeds around a
    /// connection that is still checked out.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn evict_waits_for_a_connection_still_checked_out() {
        let dir = tempfile::tempdir().unwrap();
        let pool = Arc::new(
            open_at(&dir.path().join("agent.db"), Some(&[7u8; 32]))
                .await
                .unwrap(),
        );

        // Two connections go back to the pool idle; a third stays out, as a
        // pass's does while its query runs.
        let a = pool.acquire().await.unwrap();
        let b = pool.acquire().await.unwrap();
        let held = pool.acquire().await.unwrap();
        drop(a);
        drop(b);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while pool.num_idle() < 2 {
            assert!(
                std::time::Instant::now() < deadline,
                "the two dropped connections never returned to the pool idle"
            );
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        assert_eq!(pool.size(), 3, "the setup is two idle and one checked out");

        let map: UserDbMap = Arc::new(RwLock::new(HashMap::new()));
        map.write().unwrap().insert(
            "owner".to_string(),
            UserDbSlot::Live(Arc::new(tokio::sync::OnceCell::from(Arc::clone(&pool)))),
        );

        let released = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let holder = tokio::spawn({
            let released = Arc::clone(&released);
            async move {
                tokio::time::sleep(std::time::Duration::from_millis(300)).await;
                released.store(true, std::sync::atomic::Ordering::SeqCst);
                drop(held);
            }
        });

        evict(&map, "owner").await;

        assert!(
            released.load(std::sync::atomic::Ordering::SeqCst),
            "evict returned while a connection was still checked out"
        );
        assert_eq!(
            pool.size(),
            0,
            "evict returned with {} connection(s) still open — each one a worker \
             thread that can still be running SQLCipher when the process exits",
            pool.size()
        );
        holder.await.unwrap();
    }

    /// `evict` also closes a connection that goes back to the pool **idle after
    /// `close()` has already emptied the idle queue**, which is what a task aborted
    /// mid-query leaves behind.
    ///
    /// The shape is `shutdown`'s own: the device log is stopped with `abort()`, its
    /// connection is dropped while its worker is still running the statement, and
    /// sqlx's `return_to_pool` checks `is_closed()` (still false), then waits on a ping
    /// queued behind that statement. `close()` pops the idle queue, then waits in its
    /// last `acquire`. The connection is released into the idle queue and its permit
    /// comes back, `close()` returns, and that idle connection is in a closed pool that
    /// nothing will ever close. `the_daemons_pools_are_closed_when_a_test_env_drops`
    /// finds one left in the machine pool in a loaded `just test` when `close_pool`
    /// waits for `size()` to fall, because it never does.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn evict_closes_a_connection_returned_idle_after_close_emptied_the_queue() {
        let dir = tempfile::tempdir().unwrap();
        let pool = Arc::new(
            open_at(&dir.path().join("agent.db"), Some(&[7u8; 32]))
                .await
                .unwrap(),
        );

        // A statement that runs for a while on its worker, from a task that is then
        // aborted — the connection is dropped mid-query, as an aborted log's is.
        let slow = tokio::spawn({
            let pool = Arc::clone(&pool);
            async move {
                let mut conn = pool.acquire().await.unwrap();
                let _ = sqlx::query(
                    "WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM c \
                     WHERE x < 3000000) SELECT count(*) FROM c",
                )
                .fetch_one(&mut *conn)
                .await;
            }
        });
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        slow.abort();
        let _ = slow.await;
        // Let `return_to_pool` run past its `is_closed()` check into the ping.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert_eq!(
            pool.size(),
            1,
            "the setup is one connection on its way back"
        );

        let map: UserDbMap = Arc::new(RwLock::new(HashMap::new()));
        map.write().unwrap().insert(
            "owner".to_string(),
            UserDbSlot::Live(Arc::new(tokio::sync::OnceCell::from(Arc::clone(&pool)))),
        );

        let started = std::time::Instant::now();
        evict(&map, "owner").await;

        assert_eq!(
            pool.size(),
            0,
            "evict returned after {:?} with {} connection(s) still open",
            started.elapsed(),
            pool.size()
        );
        assert!(
            started.elapsed() < super::super::POOL_DRAIN_LIMIT,
            "evict emptied the pool only by waiting out the drain limit ({:?})",
            started.elapsed()
        );
    }

    /// The journal decision: a person's database, opened keyed as `open_user_agent_db` opens it, runs WAL
    /// with FULL sync, so a read another connection holds open does not hold back
    /// a commit. Under the rollback journal `open_at` ran before, the revoke below
    /// waited for the held read and, past the 5 s busy timeout, failed; the person
    /// could not revoke a browser while anything else was reading their database.
    ///
    /// What WAL changes is also pinned: the held read keeps the row in its
    /// snapshot until it ends. A read started after the revoke answers does not.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_persons_database_runs_wal_so_a_held_read_holds_back_no_revoke() {
        use kotton_device::config::web_shell_db::{add_browser_device, revoke_browser_device};
        use std::time::Duration;

        let dir = tempfile::tempdir().unwrap();
        let pool = open_at(&dir.path().join("agent.db"), Some(&[7u8; 32]))
            .await
            .unwrap();
        USER_MIGRATOR.run(&pool).await.unwrap();

        let mode: String = sqlx::query_scalar("PRAGMA journal_mode")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(mode, "wal", "a person's database runs WAL");
        // 2 is FULL: a commit that answered survives power loss, as it did
        // under the rollback journal.
        let sync: i64 = sqlx::query_scalar("PRAGMA synchronous")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(sync, 2, "a person's database fsyncs every commit");

        let id = add_browser_device(&pool, "u", "phone", &[7; 32])
            .await
            .unwrap();
        let count = "SELECT COUNT(*) FROM browser_devices";
        let mut held = pool.acquire().await.unwrap();
        sqlx::query("BEGIN").execute(&mut *held).await.unwrap();
        let before: i64 = sqlx::query_scalar(count)
            .fetch_one(&mut *held)
            .await
            .unwrap();
        assert_eq!(before, 1);

        let answer = tokio::time::timeout(
            Duration::from_secs(1),
            revoke_browser_device(&pool, "u", "phone"),
        )
        .await
        .expect("the revoke waited on a read another connection holds open");
        assert_eq!(answer.unwrap(), Some(id));

        let after: i64 = sqlx::query_scalar(count).fetch_one(&pool).await.unwrap();
        assert_eq!(
            after, 0,
            "a read started after the revoke answered saw the row"
        );
        let snapshot: i64 = sqlx::query_scalar(count)
            .fetch_one(&mut *held)
            .await
            .unwrap();
        assert_eq!(snapshot, 1, "the read held from before keeps its snapshot");
        sqlx::query("COMMIT").execute(&mut *held).await.unwrap();
    }

    /// What WAL puts beside a person's database while it is open — the `-wal`,
    /// holding every commit since the last checkpoint, and the `-shm` index over
    /// it — carries none of it in the clear. SQLCipher encrypts WAL frames as it
    /// does pages; this reads the files with the pool still open, before a close
    /// checkpoints the `-wal` away, which is the state a person's disk is in
    /// whenever their daemon runs.
    #[tokio::test]
    async fn a_persons_wal_holds_no_plaintext_while_the_database_is_open() {
        const MARKER: &str = "a-browser-named-plainly";
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.db");
        let pool = open_at(&path, Some(&[7u8; 32])).await.unwrap();
        USER_MIGRATOR.run(&pool).await.unwrap();
        kotton_device::config::web_shell_db::add_browser_device(&pool, "u", MARKER, &[7; 32])
            .await
            .unwrap();

        let wal = std::fs::read(dir.path().join("agent.db-wal"))
            .expect("an open WAL database has a -wal");
        assert!(
            !wal.is_empty(),
            "the commit is in the -wal, or this proves nothing"
        );
        for name in ["agent.db-wal", "agent.db-shm", "agent.db"] {
            let bytes = std::fs::read(dir.path().join(name)).unwrap();
            assert!(
                !bytes.windows(MARKER.len()).any(|w| w == MARKER.as_bytes()),
                "{name} carries the browser's name in the clear"
            );
            assert!(
                !bytes.starts_with(b"SQLite format 3\0"),
                "{name} begins with the plaintext SQLite header"
            );
        }
        drop(pool);
    }
}
