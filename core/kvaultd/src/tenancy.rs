// SPDX-License-Identifier: AGPL-3.0-or-later
//! Who a vault keeps for, and dropping exactly one of them (RFC-0084;
//! `TASK-a-landlord-can-only-drop-every-tenant-at-once`).
//!
//! A tenant is a name the landlord gave at the invite — the pool's user id —
//! and every thing the vault holds for them is keyed by it:
//!
//! | Where | What |
//! |---|---|
//! | the shelf, through `Shelves::open(user_id, mount, path)` | the sealed pool, one tree per drive (`crate::drives`): `users/<id>/data/` and `users/<id>/drives/<tree>/` on the disk, `<prefix>/<id>/<mount>/` in a bucket |
//! | `users/<id>/` | the identity chain (`identity/kel.json`), the sealed recovery copy (`recovery.json`), the pool's configuration |
//! | `system/users.json`, `system/device_routing.json` | the tenant's registry entry and their routes |
//! | the secrets store | the per-user labels, and each mount's pinned key domain |
//! | `system/agent.db` | every row of every table with a `user_id` column: `paired_nodes` (the pairing), `pool_quotas`, `held_doors`, `held_deliveries`, `carried_messages`, `tenant_drives` (each made drive's sealed name), and the device tables a vault leaves empty |
//! | this process | the resident pool, its meter, sessions, reassembly buffers, the chain's tip and recovery authorities at the handshake, the paired-key allowlist and the relay reservations it drives, the held doors' reservations |
//!
//! **The drop finds all of it by the user id and by nothing else.** In
//! particular never by a device's name: `paired_nodes.id` is the name the
//! paired device *announced* in the ceremony, the tenant's to choose, and a
//! delete keyed by it could take a row another tenant's device announced under
//! the same name (`TASK-two-tenants-whose-devices-share-a-name-unpair-each-other-at-a-vault`).
//! The rows are swept by `user_id` in every table that has one, found in the
//! schema rather than listed here, so a table added later is swept without
//! anyone remembering to add it. What memory holds is then recomputed from what
//! is left — the allowlist from the remaining tenants' rows, the handshake's
//! identities from the remaining tenants' chains — rather than subtracted, so
//! an identity or a key two names share survives the one being dropped.
//!
//! **The walk admits its listing** (kotton #310; the rule is kotton #265's).
//! A shelf is emptied by walking its own listing and deleting each key
//! ([`clear_shelf`]), here for a drop and in `crate::drives` for a retire. The
//! listing is what is on the disk or in the bucket, and a file whose name
//! decodes to `../x` lists as that key, which the store will not delete: it
//! names a path outside the mount root. So each listed key is parsed into a
//! [`StorageKey`] where the listing enters the walk, and only an admitted key
//! is deleted or walked into. A key that is not canonical is no object any
//! device wrote, since a store writes only canonical keys; it is refused,
//! logged and counted ([`Cleared::refused`]), and the walk goes on, as a
//! drive move and a sync pass treat it. No second check stands before the
//! delete: the key it is handed is already a `StorageKey`.
//!
//! **What the walk refused goes with the directory, not by its key.** Kept
//! and counted, such an object would be left under a tree or a tenant that no
//! longer exists, owned by nobody and reachable by no verb: a leak, not
//! caution. So once every canonical object is deleted by key, the retire
//! removes the tree's directory whole, and the drop the tenant's directory
//! whole, and the refused file goes with it. Nothing a canonical key names is
//! deleted that way, since by then the walk has deleted each of those and
//! nothing was left for the removal but what no key names; and nothing outside
//! the directory is reached, since the removal is of the directory and never
//! of a path a listing spelled. On a bucket there is no directory, and the
//! shelf seam (`kotton_sys::store::SyncableStore`) has no delete by prefix, so
//! there the refused object stays: the vault lists the shelf once more after
//! the removal and logs that it still holds something ([`left_on`]), rather
//! than keeping it silently. A delete by prefix at the seam is what closes it.
//!
//! **What a drop is, under Article VII.** It removes the tenant from this
//! vault's index: access, not data. A tenant's data is theirs and on their own
//! devices; the vault held a sealed copy it could not read, and forgets it. A
//! device of theirs that holds only the phrase can no longer recover *from
//! here*, which is what the landlord's confirmation says before it runs.
//!
//! **No permission check.** The door is a local socket and who reaches it is
//! the landlord's policy (RFC-0084, "The landlord's door"); the landlord owns
//! the disk and can delete the volume underneath a running vault. The verb is
//! the scalpel that makes destroying everybody a choice rather than the only
//! instrument, and it limits the landlord in nothing.

use crate::peer::{capacity, PeerContext};
use kotton_common::crypto::kdf_labels;
use kotton_device::users::residency::Residency as _;
use kotton_device::users::DeviceUsers as _;
use kotton_session::service::tokens::SessionMap;
use kotton_store::{NotCanonical, StorageKey};
use kotton_sys::store::SyncableStore;
use kotton_wire::ipc::VaultTenant;
use sqlx::{Row as _, SqlitePool};
use std::collections::BTreeSet;
use std::io;
use std::path::{Component, Path};
use std::sync::Arc;

/// Is `name` something a tenant can be called and the drop can take: one
/// ordinary path component, so `users/<name>` names one directory under the
/// base and `<prefix>/<name>/` one prefix in a bucket, and never a parent or
/// a sibling's.
pub fn is_tenant_name(name: &str) -> bool {
    let mut parts = Path::new(name).components();
    matches!(
        (parts.next(), parts.next()),
        (Some(Component::Normal(c)), None) if c == name
    ) && !name.contains(['/', '\\', '\0'])
}

/// Every table in the machine db with a `user_id` column — the tables whose
/// rows belong to one tenant each. Read from the schema, so the drop reaches a
/// table added after this was written.
pub async fn tenant_tables(db: &SqlitePool) -> io::Result<Vec<String>> {
    let rows = sqlx::query(
        "SELECT m.name AS name FROM sqlite_master AS m, pragma_table_info(m.name) AS p
         WHERE m.type = 'table' AND p.name = 'user_id' ORDER BY m.name",
    )
    .fetch_all(db)
    .await
    .map_err(io::Error::other)?;
    Ok(rows.into_iter().map(|r| r.get::<String, _>("name")).collect())
}

fn quoted(table: &str) -> String {
    format!("\"{}\"", table.replace('"', "\"\""))
}

/// Delete every row keyed by `user_id`, in every tenant table, in one
/// transaction — and only by `user_id`. Returns the rows removed per table.
pub async fn sweep(db: &SqlitePool, user_id: &str) -> io::Result<Vec<(String, u64)>> {
    let tables = tenant_tables(db).await?;
    let mut tx = db.begin().await.map_err(io::Error::other)?;
    let mut removed = Vec::with_capacity(tables.len());
    for table in tables {
        let n = sqlx::query(&format!("DELETE FROM {} WHERE user_id = ?", quoted(&table)))
            .bind(user_id)
            .execute(&mut *tx)
            .await
            .map_err(io::Error::other)?
            .rows_affected();
        removed.push((table, n));
    }
    tx.commit().await.map_err(io::Error::other)?;
    Ok(removed)
}

/// Every name this vault keeps anything under: the registry, the resident
/// pools, a directory under `users/`, or a row in any tenant table. A name the
/// landlord set a quota for and has not yet admitted is one — the vault keeps
/// a number for it — and so is what a drop interrupted part-way left behind,
/// so running the drop again finishes it.
pub async fn names(ctx: &PeerContext) -> io::Result<BTreeSet<String>> {
    let base = ctx.runtime.base_dir();
    let mut names: BTreeSet<String> = ctx.pools.ids().into_iter().collect();
    if let Ok(registry) = kotton_device::registry::load_users(&base.join("system")) {
        names.extend(registry.users.into_iter().map(|u| u.user_id));
    }
    if let Ok(dirs) = std::fs::read_dir(base.join("users")) {
        for entry in dirs.flatten() {
            if entry.path().is_dir() {
                if let Some(name) = entry.file_name().to_str() {
                    names.insert(name.to_string());
                }
            }
        }
    }
    for table in tenant_tables(&ctx.db).await? {
        let rows = sqlx::query(&format!("SELECT DISTINCT user_id FROM {}", quoted(&table)))
            .fetch_all(ctx.db.as_ref())
            .await
            .map_err(io::Error::other)?;
        names.extend(rows.into_iter().map(|r| r.get::<String, _>("user_id")));
    }
    Ok(names)
}

/// One tenant's readout: bytes held, the number they are held to, and how
/// many of their devices are paired here — a count, never a device's name.
async fn readout(ctx: &PeerContext, user_id: &str) -> io::Result<VaultTenant> {
    let (held, quota) = match capacity(ctx, user_id).await {
        kotton_wire::ipc::UserResponse::VaultCapacityResult { held, quota } => (held, quota),
        _ => (0, ctx.meter.quota(user_id)),
    };
    let devices: i64 = sqlx::query("SELECT COUNT(*) AS n FROM paired_nodes WHERE user_id = ?")
        .bind(user_id)
        .fetch_one(ctx.db.as_ref())
        .await
        .map_err(io::Error::other)?
        .get("n");
    Ok(VaultTenant {
        user_id: user_id.to_string(),
        held,
        quota,
        devices: u32::try_from(devices).unwrap_or(u32::MAX),
    })
}

/// Every tenant, by name, with their readout.
pub async fn list(ctx: &PeerContext) -> io::Result<Vec<VaultTenant>> {
    let _steady = ctx.tenancy.read().await;
    let mut out = Vec::new();
    for name in names(ctx).await? {
        out.push(readout(ctx, &name).await?);
    }
    Ok(out)
}

/// What a walk of one shelf did ([`clear_shelf`]).
#[derive(Debug, Default)]
pub struct Cleared {
    /// The objects it deleted.
    pub removed: u64,
    /// Each key the shelf listed that is not a storage key, and why: refused
    /// where the listing entered the walk, so never deleted by key and never
    /// walked into. What becomes of the object is the caller's directory
    /// removal (module doc, "The walk admits its listing").
    pub refused: Vec<NotCanonical>,
}

/// Delete every object on one shelf, walked through its own listing — the
/// same walk the meter measures with, so a bucket is emptied as a directory
/// is. Each listed key is admitted as a [`StorageKey`] where the listing enters
/// the walk, and only an admitted key is deleted or listed under; one that is
/// not canonical is logged and returned in [`Cleared::refused`] (kotton #310).
pub async fn clear_shelf(shelf: &dyn SyncableStore) -> io::Result<Cleared> {
    let mut cleared = Cleared::default();
    let mut pending: Vec<Option<StorageKey>> = vec![None];
    while let Some(prefix) = pending.pop() {
        let at = prefix.as_ref().map_or(Path::new(""), StorageKey::as_path);
        let entries = shelf
            .list(at)
            .await
            .map_err(|e| io::Error::other(format!("listing the shelf at {at:?}: {e}")))?;
        for e in entries {
            let key = match StorageKey::parse(&e.key) {
                Ok(key) => key,
                Err(refused) => {
                    tracing::warn!(key = ?refused.key, why = refused.why, "the shelf listed a key that is not a storage key; the walk refused it");
                    cleared.refused.push(refused);
                    continue;
                }
            };
            if e.is_dir {
                pending.push(Some(key));
            } else {
                shelf
                    .delete(key.as_path())
                    .await
                    .map_err(|err| io::Error::other(format!("deleting {key:?} from the shelf: {err}")))?;
                cleared.removed += 1;
            }
        }
    }
    Ok(cleared)
}

/// Whether `shelf` still lists anything once its directory was removed: what
/// a walk refused and a directory removal did not take, on a bucket (module
/// doc). Logged by the caller; a listing that fails is read as nothing left
/// to say, since the walk itself has already listed this shelf.
pub async fn left_on(shelf: &dyn SyncableStore) -> bool {
    shelf.list(Path::new("")).await.is_ok_and(|left| !left.is_empty())
}

/// Drop exactly one tenant: everything in the module table, found by their
/// user id, and nothing of anyone else's. Answers their readout as it stood
/// before.
///
/// In three steps, standing first so nothing is admitted for them from the
/// first step on: the rows, and what memory projects from them; the bytes on
/// the shelf; then the directory, the registry entry and the keychain. The
/// registry entry goes last, so a drop that fails part-way leaves the name
/// listed and running it again finishes it.
///
/// Holds the vault still for the first step only (`PeerContext::tenancy`,
/// write side): no peer request is mid-flight for anyone while standing is
/// taken away, so no write lands in the pool afterwards, and every request
/// that waited finds the tenant a stranger. From then on nothing can reach
/// their pool, so the shelf walk — long on a large bucket — runs with every
/// other tenant served beside it. Drops run one at a time (`PeerContext::drops`).
///
/// A `DeviceJoin` or `DeviceInvite` for the same name that completes while a
/// drop runs admits that name afresh: the landlord's own race, and a second
/// drop cleans it.
pub async fn drop_tenant(
    ctx: &PeerContext,
    sessions: &SessionMap,
    user_id: &str,
) -> io::Result<VaultTenant> {
    if !is_tenant_name(user_id) {
        return Err(io::Error::other(format!(
            "'{user_id}' is not a tenant's name: a tenant is one path component"
        )));
    }
    let _one_drop = ctx.drops.lock().await;
    let alone = ctx.tenancy.write().await;
    if !names(ctx).await?.contains(user_id) {
        return Err(io::Error::other(format!("this vault keeps nothing under '{user_id}'")));
    }
    let before = readout(ctx, user_id).await?;
    let base = ctx.runtime.base_dir().to_path_buf();

    // The identity the handshake knows them by: the registry's AID and the
    // chain's, which agree unless a file was edited by hand.
    let mut aids = BTreeSet::new();
    if let Some(aid) = ctx.runtime.user_aid(user_id) {
        aids.insert(aid);
    }
    if let Some(tip) = kotton_identity::kel_store::load_chain(&base, user_id)
        .unwrap_or_default()
        .last()
    {
        aids.insert(tip.aid.to_string());
    }
    // Where their pool rests. A vault makes one mount per pool, "local"; a
    // pool that is not resident is read as that one.
    let mounts = match ctx.pools.get(user_id) {
        Some(store) => store.shelf_mounts(),
        None => vec![("local".to_string(), base.join("users").join(user_id).join("data"))],
    };

    // 1. Standing: every row keyed by them, then what memory projects.
    let swept = sweep(&ctx.db, user_id).await?;
    ctx.pools.remove(user_id);
    ctx.meter.forget(user_id).await;
    kotton_session::service::tokens::remove_user(sessions, user_id);
    ctx.reassembly.lock().await.retain(|key, _| key.0 != user_id);
    let admission = ctx.runtime.admission();
    for aid in &aids {
        admission.forget(aid);
    }
    let remaining = ctx.pools.all();
    let remaining_ids: Vec<String> = remaining.iter().map(|(id, _)| id.clone()).collect();
    kotton_device::users::admission::reproject(&base, &remaining_ids, &admission);
    let stores: Vec<(String, Arc<dyn kotton_peer::membership::MemberStore>)> = remaining
        .into_iter()
        .map(|(id, s)| (id, s as Arc<dyn kotton_peer::membership::MemberStore>))
        .collect();
    kotton_peer::daemon::nodes::reproject_allowlist(&stores, &ctx.db, &ctx.runtime.paired_keys()).await;
    crate::doors::refresh(&ctx.runtime, &ctx.db).await;
    // Nothing of theirs is reachable now; everyone else is served again.
    drop(alone);

    // 2. The bytes on the shelf, through the shelf: on a bucket this is the
    // only way the objects go, and on the disk it is the same walk.
    let mut objects = 0u64;
    let mut keys_refused = 0usize;
    let mut shelves = Vec::with_capacity(mounts.len());
    for (mount, path) in &mounts {
        let shelf = ctx.runtime.shelves().open(user_id, mount, path);
        let cleared = clear_shelf(shelf.as_ref()).await?;
        objects += cleared.removed;
        keys_refused += cleared.refused.len();
        shelves.push((mount, shelf));
        let _ = ctx
            .runtime
            .secrets()
            .delete_secret(&kdf_labels::sealed_mount_domain(user_id, mount));
    }

    // 3. The directory — chain, recovery copy, configuration — the registry
    // entry and routes, and the per-user keychain labels. `logout_user` is the
    // device's own "remove a user", which leaves no trace in the keychain.
    let registered = kotton_device::registry::load_users(&base.join("system"))
        .map(|r| r.users.iter().any(|u| u.user_id == user_id))
        .unwrap_or(false);
    if registered {
        kotton_device::users::commands::logout_user(ctx.runtime.as_ref(), user_id)
            .await
            .map_err(|e| io::Error::other(format!("{e:#}")))?;
    } else {
        kotton_common::fs::remove_dir_all_retrying(&base.join("users").join(user_id))
            .map_err(|e| io::Error::other(e.to_string()))?;
        kotton_identity::provisioning::delete_all_user_secrets(ctx.runtime.secrets(), user_id);
    }
    // What the walk refused went with the directory; on a bucket nothing
    // removes it, and the vault says so rather than keeping it silently.
    if keys_refused > 0 {
        for (mount, shelf) in &shelves {
            if left_on(shelf.as_ref()).await {
                tracing::warn!(user_id, mount = %mount, "a dropped tenant's shelf still holds objects whose keys are not storage keys; nothing at the shelf seam removes them by prefix");
            }
        }
    }
    tracing::info!(
        user_id,
        objects,
        keys_refused,
        rows = ?swept.iter().filter(|(_, n)| *n > 0).collect::<Vec<_>>(),
        "dropped a tenant"
    );
    Ok(before)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_tenants_name_is_one_path_component() {
        for ok in ["alice", "bob's laptop", "a.b", "..alice"] {
            assert!(is_tenant_name(ok), "{ok}");
        }
        for bad in ["", ".", "..", "../system", "a/b", "/alice", "a\\b", "alice/", "a\0b"] {
            assert!(!is_tenant_name(bad), "{bad:?}");
        }
    }

    /// Two tenants with a row in every table a vault keeps per tenant; the
    /// sweep of one takes all of theirs and none of the other's, and the
    /// tables it finds are the ones a tenant has rows in.
    #[tokio::test]
    async fn the_sweep_takes_every_row_of_one_tenant_and_none_of_anothers() {
        let dir = tempfile::tempdir().unwrap();
        let db = kotton_device::db::open_machine_db(dir.path().join("agent.db"))
            .await
            .unwrap();
        crate::meter::init(&db).await.unwrap();
        crate::doors::init(&db).await.unwrap();
        crate::carry::init(&db).await.unwrap();
        crate::drives::init(&db).await.unwrap();

        let tables = tenant_tables(&db).await.unwrap();
        for t in ["paired_nodes", "pool_quotas", "held_doors", "held_deliveries", "carried_messages", "tenant_drives"] {
            assert!(tables.iter().any(|x| x == t), "{t} is swept: {tables:?}");
        }

        for (i, user) in ["alice", "bob"].into_iter().enumerate() {
            let n = i as u8 + 1;
            sqlx::query(
                "INSERT INTO paired_nodes (id, user_id, device_did, public_key, addresses, paired_at)
                 VALUES (?, ?, ?, ?, '[]', 0)",
            )
            .bind(format!("{user}'s laptop"))
            .bind(user)
            .bind(format!("did:key:{user}"))
            .bind(vec![n; 32])
            .execute(&db)
            .await
            .unwrap();
            sqlx::query("INSERT INTO pool_quotas (user_id, quota) VALUES (?, 4096)")
                .bind(user)
                .execute(&db)
                .await
                .unwrap();
            sqlx::query(
                "INSERT INTO held_doors (user_id, epoch, handle_did, seed, admit) VALUES (?, 1, ?, 's', 'a')",
            )
            .bind(user)
            .bind(format!("did:key:door-{user}"))
            .execute(&db)
            .await
            .unwrap();
            sqlx::query(
                "INSERT INTO held_deliveries (user_id, handle_did, ephemeral_pub, sealed, received_at)
                 VALUES (?, 'h', ?, '{}', 0)",
            )
            .bind(user)
            .bind(format!("eph-{user}"))
            .execute(&db)
            .await
            .unwrap();
            sqlx::query(
                "INSERT INTO carried_messages (user_id, ephemeral_pub, sealed, doors, handed_at, attempts, next_at)
                 VALUES (?, ?, '{}', '[]', 0, 0, 0)",
            )
            .bind(user)
            .bind(format!("eph-{user}"))
            .execute(&db)
            .await
            .unwrap();
            sqlx::query("INSERT INTO tenant_drives (user_id, tree, sealed_name, made_at) VALUES (?, 'drive-00', x'01', 0)")
                .bind(user)
                .execute(&db)
                .await
                .unwrap();
        }

        // The vault's operator credential is nobody's tenancy: its table has no
        // `user_id`, so no drop's sweep reaches it.
        assert!(!tables.iter().any(|x| x == "operator_key"), "operator_key is not swept: {tables:?}");
        // Nor is the record of what the operators did — a drop of alice's pool
        // included, which is the landlord's record and not alice's tenancy.
        assert!(!tables.iter().any(|x| x == "operator_acts"), "operator_acts is not swept: {tables:?}");
        kotton_peer::daemon::db::enrol_operator_key(&db, &[9u8; 32]).await.unwrap();

        let removed = sweep(&db, "alice").await.unwrap();
        assert_eq!(
            kotton_peer::daemon::db::operator_keys(&db).await.unwrap(),
            vec![[9u8; 32]],
            "a drop leaves the operator credential enrolled"
        );
        for t in ["paired_nodes", "pool_quotas", "held_doors", "held_deliveries", "carried_messages", "tenant_drives"] {
            assert_eq!(
                removed.iter().find(|(x, _)| x == t).map(|(_, n)| *n),
                Some(1),
                "one row of alice's in {t}"
            );
        }
        for table in &tables {
            let count = |user: &'static str| {
                let db = &db;
                let sql = format!("SELECT COUNT(*) AS n FROM {} WHERE user_id = ?", quoted(table));
                async move {
                    sqlx::query(&sql)
                        .bind(user)
                        .fetch_one(db)
                        .await
                        .unwrap()
                        .get::<i64, _>("n")
                }
            };
            assert_eq!(count("alice").await, 0, "nothing of alice's is left in {table}");
        }
        for t in ["paired_nodes", "pool_quotas", "held_doors", "held_deliveries", "carried_messages", "tenant_drives"] {
            let n: i64 = sqlx::query(&format!("SELECT COUNT(*) AS n FROM {t} WHERE user_id = 'bob'"))
                .fetch_one(&db)
                .await
                .unwrap()
                .get("n");
            assert_eq!(n, 1, "bob's row in {t} is untouched");
        }
    }
}
