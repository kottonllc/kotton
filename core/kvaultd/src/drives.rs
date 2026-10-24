// SPDX-License-Identifier: AGPL-3.0-or-later
//! A tenant's drives at this vault: a drive is a tenancy on a vault, and a
//! person may have several, on one vault or many.
//!
//! **What a drive is here: a sealed tree of its own in the tenant's pool.**
//! The pool a vault kept for each tenant before is the tenancy's own tree, the
//! mount `local` — the person's first drive here, migrated in place by being
//! read as one: nothing moved, and a vault that never saw a made drive answers
//! exactly as it did. Every drive made after it is another mount of the same
//! pool, kept beside it:
//!
//! | Drive | Mount (the tree the sealed verbs name) | On the disk | Its name |
//! |---|---|---|---|
//! | the tenancy's own | `local` | `users/<id>/data/` | none sealed; every device calls it `personal` |
//! | each made one | `drive-<32 hex>` (`MadeDrive::tree`) | `users/<id>/drives/<tree>/` | sealed, in `tenant_drives` |
//!
//! On a bucket each is `<prefix>/<id>/<tree>/`, through the same `Shelves`
//! seam the first drive rests on. Each tree pins its own key domain at its
//! first sealed write (`sealed_mount_domain(<id>, <tree>)`), as `local` does,
//! so a write in another domain is refused per drive.
//!
//! **What the vault learns, and what it does not.** How many drives a tenant
//! has, how large each is, and when each was made: the shape of what it
//! already keeps. Not what any is called — the name arrives sealed under the
//! person's key, bound to the tree, and is handed back as it came — and not
//! which of its drives is which of another vault's: a made drive's id is
//! minted by the person's device fresh for each vault it is kept on, so a
//! drive moved here from elsewhere carries no id the other landlord holds.
//!
//! **Who reaches it: a tenant's device, to its own pool**, through the four
//! tenant verbs (`TenantDriveMake`, `TenantDrives`, `TenantDriveName`,
//! `TenantDriveRetire`) that
//! `crate::peer::reaches` gives `Paired` standing and nothing else. A made
//! drive is named on the wire by a `MadeDrive`, sixteen bytes, so the tree a
//! verb names is always `drive-` and hex: one path component, never `local`,
//! and the tenancy's own tree cannot be retired by any of them. No check of a
//! caller's string stands in for that; the type is the key.
//!
//! **Everything here is the tenant's, keyed by their user id**: the trees are
//! mounts of their pool, which the landlord's drop clears mount by mount
//! (`crate::tenancy`), and `tenant_drives` has a `user_id` column, so the
//! drop's sweep takes its rows without being told the table exists. Every
//! drive is metered against the one quota (`crate::peer::pool_shelves`).
//!
//! **What is not here.** A drive is moved by a device of the person's, which
//! reads its sealed tree from one vault and writes it to another
//! (`kotton_device::users::drive_verbs`); a vault never dials another. The
//! tree it writes to is made under a name sealed *unfinished* and named
//! finished (`TenantDriveName`) only once the copy is verified, so a listing
//! taken mid-move never shows a second drive of the same name. A retire does
//! refuses a write in flight to the same drive ([`Trees`]): each sealed write
//! into a made drive holds the drive for reading for the whole request, and a
//! retire holds it for writing, drops any part of a write still being
//! reassembled, and takes the tree away; a write that comes after finds no
//! tree and is refused by name. So a write is either in the drive before its
//! retire begins — and was carried by the move that retires it, or it was not
//! a move's — or refused, never landed in a directory being removed. What no
//! vault-side lock holds is two devices acting on one drive at two vaults; that
//! is `kotton_device::users::drive_verbs`' module doc's lease.

use crate::peer::PeerContext;
use kotton_common::crypto::kdf_labels;
use kotton_device::users::residency::Residency as _;
use kotton_wire::ipc::{MadeDrive, TenantDrive, UserResponse, FIRST_DRIVE_TREE};
use sqlx::{Row as _, SqlitePool};
use std::io;

/// The longest sealed name a vault keeps: a name is a few words, sealed with
/// a fixed header; this bounds what a tenant can keep outside the meter.
pub const MAX_SEALED_NAME: usize = 1024;

/// Make the table the sealed names rest in, in the vault's machine db — the
/// same file and idiom as the quotas and doors (`crate::meter::init`).
pub async fn init(db: &SqlitePool) -> io::Result<()> {
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS tenant_drives (
            user_id     TEXT    NOT NULL,
            tree        TEXT    NOT NULL,
            sealed_name BLOB    NOT NULL,
            made_at     INTEGER NOT NULL,
            PRIMARY KEY (user_id, tree)
        )",
    )
    .execute(db)
    .await
    .map_err(io::Error::other)?;
    Ok(())
}

fn refused(message: impl Into<String>) -> UserResponse {
    UserResponse::Error { message: message.into() }
}

/// One lock per made drive a tenant keeps at this vault ([`PeerContext::trees`]).
#[derive(Default)]
pub struct Trees(std::sync::Mutex<std::collections::HashMap<(String, String), TreeLock>>);

/// The lock one made drive is held under ([`Trees`]).
type TreeLock = std::sync::Arc<tokio::sync::RwLock<()>>;

impl Trees {
    fn of(&self, user_id: &str, tree: &str) -> TreeLock {
        let mut held = self.0.lock().unwrap();
        held.entry((user_id.to_string(), tree.to_string())).or_default().clone()
    }
}

/// Hold `user_id`'s drive `mount` for a sealed write into it, or refuse the
/// write when it is a made drive this vault no longer keeps — retired, or
/// never made. The tenancy's own tree is never retired, and takes no hold.
pub async fn write_into(
    ctx: &PeerContext,
    user_id: &str,
    mount: &str,
) -> Result<Option<tokio::sync::OwnedRwLockReadGuard<()>>, String> {
    if MadeDrive::from_tree(mount).is_none() {
        return Ok(None);
    }
    let held = ctx.trees.of(user_id, mount).read_owned().await;
    let kept = ctx.pools.get(user_id).is_some_and(|pool| pool.get_remote(mount).is_some());
    if !kept {
        return Err(format!(
            "this vault keeps no drive for '{user_id}' under {mount}: it was retired, or never made here, so the write \
             was refused"
        ));
    }
    Ok(Some(held))
}

/// `TenantDriveMake`: a sealed tree of its own for `user_id`, under `drive`,
/// with `sealed_name` kept beside it.
///
/// The row first, in a transaction, then the tree: a tree that cannot be made
/// rolls the row back, and a row that cannot be committed takes the tree out
/// again, so a drive is listed with its name or not at all.
pub async fn make(ctx: &PeerContext, user_id: &str, drive: MadeDrive, sealed_name: Vec<u8>) -> io::Result<UserResponse> {
    let Some(pool) = ctx.pools.get(user_id) else {
        return Ok(refused(format!("this vault keeps no pool for '{user_id}'")));
    };
    if sealed_name.len() > MAX_SEALED_NAME {
        return Ok(refused(format!(
            "a drive's sealed name is at most {MAX_SEALED_NAME} bytes; this one is {}",
            sealed_name.len()
        )));
    }
    let tree = drive.tree();
    if pool.get_remote(&tree).is_some() {
        return Ok(refused(format!("this vault already keeps a drive for '{user_id}' under {tree}")));
    }
    let mut tx = ctx.db.begin().await.map_err(io::Error::other)?;
    let inserted = sqlx::query(
        "INSERT INTO tenant_drives (user_id, tree, sealed_name, made_at) VALUES (?, ?, ?, ?)",
    )
    .bind(user_id)
    .bind(&tree)
    .bind(&sealed_name)
    .bind(kotton_common::time::now_secs())
    .execute(&mut *tx)
    .await;
    if let Err(e) = inserted {
        return Ok(refused(format!("this vault could not keep a drive for '{user_id}' under {tree}: {e}")));
    }
    let path = pool.base_dir().join("drives").join(&tree);
    if let Err(e) = pool.add_shelf_tree(&tree, path, ctx.runtime.shelves()) {
        return Ok(refused(format!("this vault could not make the tree for a drive of '{user_id}': {e:#}")));
    }
    if let Err(e) = tx.commit().await {
        let _ = pool.remove_remote(&tree);
        return Err(io::Error::other(e));
    }
    tracing::info!(user_id, tree, "made a drive for a tenant");
    Ok(UserResponse::Ok)
}

/// `TenantDrives`: every drive this vault keeps for `user_id`, the tenancy's
/// own tree first, each with its sealed name and the bytes it holds now.
pub async fn list(ctx: &PeerContext, user_id: &str) -> io::Result<UserResponse> {
    let Some(pool) = ctx.pools.get(user_id) else {
        return Ok(refused(format!("this vault keeps no pool for '{user_id}'")));
    };
    let names = sqlx::query("SELECT tree, sealed_name FROM tenant_drives WHERE user_id = ?")
        .bind(user_id)
        .fetch_all(ctx.db.as_ref())
        .await
        .map_err(io::Error::other)?;
    let mut trees: Vec<String> = pool.shelf_mounts().into_iter().map(|(mount, _)| mount).collect();
    trees.sort_by_key(|t| (t != FIRST_DRIVE_TREE, t.clone()));
    let mut drives = Vec::with_capacity(trees.len());
    for tree in trees {
        // A mount of the pool that is neither the first drive nor a made one is
        // nothing a tenant's verb made, and is not one of their drives.
        if tree != FIRST_DRIVE_TREE && MadeDrive::from_tree(&tree).is_none() {
            continue;
        }
        let Some(shelf) = pool.get_remote(&tree) else { continue };
        let sealed_name = names
            .iter()
            .find(|r| r.get::<String, _>("tree") == tree)
            .map(|r| r.get::<Vec<u8>, _>("sealed_name"))
            .unwrap_or_default();
        let held = crate::meter::Meter::measure(shelf.as_ref()).await;
        drives.push(TenantDrive { tree, sealed_name, held });
    }
    Ok(UserResponse::TenantDrivesResult { drives })
}

/// `TenantDriveName`: replace the sealed name a made drive is kept under —
/// how a move names its tree finished once the copy is verified.
pub async fn name(ctx: &PeerContext, user_id: &str, drive: MadeDrive, sealed_name: Vec<u8>) -> io::Result<UserResponse> {
    if sealed_name.len() > MAX_SEALED_NAME {
        return Ok(refused(format!(
            "a drive's sealed name is at most {MAX_SEALED_NAME} bytes; this one is {}",
            sealed_name.len()
        )));
    }
    let tree = drive.tree();
    let named = sqlx::query("UPDATE tenant_drives SET sealed_name = ? WHERE user_id = ? AND tree = ?")
        .bind(&sealed_name)
        .bind(user_id)
        .bind(&tree)
        .execute(ctx.db.as_ref())
        .await
        .map_err(io::Error::other)?
        .rows_affected();
    if named == 0 {
        return Ok(refused(format!("this vault keeps no drive for '{user_id}' under {tree}")));
    }
    Ok(UserResponse::Ok)
}

/// `TenantDriveRetire`: every sealed object in the made drive's tree, then the
/// tree, its pinned key domain and its sealed name — and the pool's count
/// measured again, so the quota sees the bytes go.
///
/// Idempotent: a drive this vault no longer keeps is answered `Ok`, as one it
/// has just retired is, so a retry after a lost answer is read truly.
pub async fn retire(ctx: &PeerContext, user_id: &str, drive: MadeDrive) -> io::Result<UserResponse> {
    let Some(pool) = ctx.pools.get(user_id) else {
        return Ok(refused(format!("this vault keeps no pool for '{user_id}'")));
    };
    let tree = drive.tree();
    // Every write into the drive in flight finishes first, and none starts
    // until the tree is gone ([`Trees`]); a write still being reassembled is
    // dropped, so its next part finds no tree and is refused.
    let _retiring = ctx.trees.of(user_id, &tree).write_owned().await;
    let reassembling = format!("sealed:{tree}");
    ctx.reassembly.lock().await.retain(|(user, slot, _, _), _| !(user == user_id && *slot == reassembling));
    let Some(path) = pool.shelf_mounts().into_iter().find(|(m, _)| *m == tree).map(|(_, p)| p) else {
        // Already as asked: the tree is gone. A retire answers what the vault
        // keeps afterwards, not whether this ask was the one that removed it,
        // so a device whose first ask acted and whose answer was lost reads
        // the second ask truly. A stray name row is taken with it.
        sqlx::query("DELETE FROM tenant_drives WHERE user_id = ? AND tree = ?")
            .bind(user_id)
            .bind(&tree)
            .execute(ctx.db.as_ref())
            .await
            .map_err(io::Error::other)?;
        return Ok(UserResponse::Ok);
    };
    let shelf = ctx.runtime.shelves().open(user_id, &tree, &path);
    let objects = crate::tenancy::clear_shelf(shelf.as_ref()).await?;
    pool.remove_remote(&tree).map_err(|e| io::Error::other(format!("{e:#}")))?;
    let _ = ctx.runtime.secrets().delete_secret(&kdf_labels::sealed_mount_domain(user_id, &tree));
    sqlx::query("DELETE FROM tenant_drives WHERE user_id = ? AND tree = ?")
        .bind(user_id)
        .bind(&tree)
        .execute(ctx.db.as_ref())
        .await
        .map_err(io::Error::other)?;
    if path.starts_with(pool.base_dir()) {
        let _ = kotton_common::fs::remove_dir_all_retrying(&path);
    }
    ctx.meter.set(user_id, crate::peer::measure_pool(&pool).await);
    tracing::info!(user_id, tree, objects, "retired a tenant's drive");
    Ok(UserResponse::Ok)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::VaultHost;
    use crate::meter::Meter;
    use crate::residency::Pools;
    use kotton_device::config::RuntimeConfig;
    use kotton_device::DeviceRuntime;
    use kotton_store::runtime::user::UserStore;
    use std::collections::HashMap;
    use std::sync::Arc;

    /// A vault with two tenants' pools, alice's and bob's, keyless as a
    /// vault's are.
    async fn a_vault(dir: &std::path::Path) -> PeerContext {
        let secrets = Arc::new(kotton_secret::MemorySecrets::new());
        let runtime = DeviceRuntime::new_with_secrets(dir.join("vault"), RuntimeConfig::default(), secrets)
            .await
            .unwrap();
        let pools = Pools::new();
        for user in ["alice", "bob"] {
            let pool = UserStore::create(
                user,
                &format!("did:key:z{user}"),
                dir.join("vault").join("users").join(user),
                kotton_store::runtime::UserKeys::keyless(),
                runtime.shelves(),
            )
            .unwrap();
            pool.save_config().unwrap();
            pools.insert(user.into(), Arc::new(pool));
        }
        let db = Arc::new(SqlitePool::connect("sqlite::memory:").await.unwrap());
        kotton_device::db::MIGRATOR.run(db.as_ref()).await.unwrap();
        init(&db).await.unwrap();
        PeerContext {
            runtime: Arc::new(runtime),
            pools,
            db,
            meter: Arc::new(Meter::new(None)),
            reassembly: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            tenancy: tokio::sync::RwLock::new(()),
            drops: tokio::sync::Mutex::new(()),
            trees: Default::default(),
        }
    }

    async fn write(ctx: &PeerContext, user: &str, tree: &str, path: &str, body: &[u8]) {
        let host = VaultHost { runtime: &ctx.runtime, pools: &ctx.pools };
        let hash = blake3::hash(body).to_hex().to_string();
        let answer = kotton_device::users::files::write_sealed(
            &host,
            user.into(),
            tree.into(),
            path.into(),
            body.to_vec(),
            "domain".into(),
            0,
            body.len() as u64,
            hash,
            None,
        )
        .await
        .unwrap();
        assert!(matches!(answer, UserResponse::Ok), "{answer:?}");
    }

    async fn keys(ctx: &PeerContext, user: &str, tree: &str) -> Vec<String> {
        ctx.pools.get(user).unwrap().list_sealed(tree, "").await.unwrap().into_iter().map(|(k, _, _)| k).collect()
    }

    async fn listed(ctx: &PeerContext, user: &str) -> Vec<TenantDrive> {
        match list(ctx, user).await.unwrap() {
            UserResponse::TenantDrivesResult { drives } => drives,
            other => panic!("{other:?}"),
        }
    }

    /// **A vault keeps several drives for one tenant, each a sealed tree of
    /// its own.** Two drives made for alice beside her first: what is written
    /// to each is in that one and no other, the listing names all three — the
    /// first first, each made one with the sealed name it was made with and
    /// the bytes it holds — and bob, on the same vault, has his first drive
    /// alone. Retiring one takes its objects and its name and leaves the rest;
    /// and a reload of the pool finds the drive that remains.
    #[tokio::test]
    async fn a_vault_keeps_several_drives_for_one_tenant_each_a_tree_of_its_own() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = a_vault(dir.path()).await;
        let (photos, work) = (MadeDrive([1; 16]), MadeDrive([2; 16]));
        for (drive, name) in [(photos, b"sealed photos".to_vec()), (work, b"sealed work".to_vec())] {
            assert!(matches!(make(&ctx, "alice", drive, name).await.unwrap(), UserResponse::Ok));
        }
        match make(&ctx, "alice", photos, vec![]).await.unwrap() {
            UserResponse::Error { message } => assert!(message.contains("already keeps"), "{message}"),
            other => panic!("one id was made twice: {other:?}"),
        }

        write(&ctx, "alice", FIRST_DRIVE_TREE, "x/first", b"first").await;
        write(&ctx, "alice", &photos.tree(), "x/photo", b"a photo").await;
        write(&ctx, "alice", &work.tree(), "x/memo", b"memo").await;
        assert_eq!(keys(&ctx, "alice", FIRST_DRIVE_TREE).await, ["x/first"]);
        assert_eq!(keys(&ctx, "alice", &photos.tree()).await, ["x/photo"]);
        assert_eq!(keys(&ctx, "alice", &work.tree()).await, ["x/memo"]);

        let drives = listed(&ctx, "alice").await;
        let said: Vec<(String, Vec<u8>)> = drives.iter().map(|d| (d.tree.clone(), d.sealed_name.clone())).collect();
        assert_eq!(
            said,
            [
                (FIRST_DRIVE_TREE.to_string(), vec![]),
                (photos.tree(), b"sealed photos".to_vec()),
                (work.tree(), b"sealed work".to_vec()),
            ]
        );
        assert!(drives.iter().all(|d| d.held > 0), "{drives:?}");
        assert_eq!(listed(&ctx, "bob").await.len(), 1, "bob has his first drive alone");
        assert!(dir.path().join("vault/users/alice/drives").join(photos.tree()).is_dir());

        assert!(matches!(retire(&ctx, "alice", work).await.unwrap(), UserResponse::Ok));
        assert_eq!(listed(&ctx, "alice").await.iter().map(|d| d.tree.clone()).collect::<Vec<_>>(), [FIRST_DRIVE_TREE.to_string(), photos.tree()]);
        assert!(!dir.path().join("vault/users/alice/drives").join(work.tree()).exists(), "the retired tree is on the disk");
        assert_eq!(keys(&ctx, "alice", &photos.tree()).await, ["x/photo"], "retiring one drive touched another");
        assert_eq!(keys(&ctx, "alice", FIRST_DRIVE_TREE).await, ["x/first"]);
        assert_eq!(
            ctx.meter.held("alice"),
            Some(listed(&ctx, "alice").await.iter().map(|d| d.held).sum::<u64>()),
            "the meter counts what is left, over every drive"
        );
        assert!(matches!(name(&ctx, "alice", photos, b"named again".to_vec()).await.unwrap(), UserResponse::Ok));
        assert_eq!(listed(&ctx, "alice").await[1].sealed_name, b"named again");
        match name(&ctx, "alice", work, b"x".to_vec()).await.unwrap() {
            UserResponse::Error { message } => assert!(message.contains("keeps no drive"), "{message}"),
            other => panic!("a retired drive was named: {other:?}"),
        }
        match name(&ctx, "bob", photos, b"x".to_vec()).await.unwrap() {
            UserResponse::Error { message } => assert!(message.contains("keeps no drive"), "{message}"),
            other => panic!("bob named alice's drive: {other:?}"),
        }
        // Idempotent: asked again — an answer lost, a retry — it is `Ok`, and
        // nothing else changes.
        assert!(
            matches!(retire(&ctx, "alice", work).await.unwrap(), UserResponse::Ok),
            "a retire asked again for a drive already gone is not Ok"
        );
        assert_eq!(keys(&ctx, "alice", &photos.tree()).await, ["x/photo"]);

        let reloaded = UserStore::load(
            "alice",
            "did:key:zalice",
            dir.path().join("vault/users/alice"),
            kotton_store::runtime::UserKeys::keyless(),
            ctx.runtime.shelves(),
        )
        .await
        .unwrap();
        assert_eq!(reloaded.read_sealed(&photos.tree(), "x/photo").await.unwrap(), b"a photo");
    }

    /// **A retire with a write in flight refuses the write** (kotton #55's
    /// last comment). A write into a made drive holds it; a retire asked
    /// meanwhile waits for that request to end, drops the part of the object
    /// still being reassembled, and takes the tree; the write's last part then
    /// finds no tree and is refused by name — nothing lands in the retired
    /// drive's directory. The first drive takes no hold and is never refused
    /// so.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_retire_with_a_write_in_flight_refuses_the_write() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = Arc::new(a_vault(dir.path()).await);
        let photos = MadeDrive([4; 16]);
        assert!(matches!(make(&ctx, "alice", photos, b"sealed".to_vec()).await.unwrap(), UserResponse::Ok));
        let body = vec![9u8; 64];
        let hash = blake3::hash(&body).to_hex().to_string();
        let part = |offset: usize| {
            let (ctx, hash, body) = (Arc::clone(&ctx), hash.clone(), body.clone());
            async move {
                let host = VaultHost { runtime: &ctx.runtime, pools: &ctx.pools };
                kotton_device::users::files::write_sealed(
                    &host,
                    "alice".into(),
                    photos.tree(),
                    "x/photo".into(),
                    body[offset..offset + 32].to_vec(),
                    "domain".into(),
                    offset as u64,
                    body.len() as u64,
                    hash,
                    Some(&ctx.reassembly),
                )
                .await
                .unwrap()
            }
        };

        // The first part, under the hold a write takes.
        let held = write_into(&ctx, "alice", &photos.tree()).await.expect("a kept drive takes the write");
        assert!(matches!(part(0).await, UserResponse::Ok), "the first part is taken");
        let retiring = tokio::spawn({
            let ctx = Arc::clone(&ctx);
            async move { retire(&ctx, "alice", photos).await.unwrap() }
        });
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        assert!(!retiring.is_finished(), "the retire did not wait for the write in flight");
        drop(held);
        assert!(matches!(retiring.await.unwrap(), UserResponse::Ok));

        // The last part comes after the retire: refused, by name.
        match write_into(&ctx, "alice", &photos.tree()).await {
            Err(message) => assert!(message.contains("keeps no drive") && message.contains("refused"), "{message}"),
            other => panic!("a write into a retired drive was let in: {:?}", other.map(|_| ())),
        }
        assert!(ctx.reassembly.lock().await.is_empty(), "the retired drive's part was kept");
        assert!(!dir.path().join("vault/users/alice/drives").join(photos.tree()).exists(), "the retired tree is on the disk");
        assert!(write_into(&ctx, "alice", FIRST_DRIVE_TREE).await.unwrap().is_none(), "the first drive took a hold");
    }

    /// A sealed name past the bound is refused, and no tree is made for it.
    #[tokio::test]
    async fn a_sealed_name_past_the_bound_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = a_vault(dir.path()).await;
        match make(&ctx, "alice", MadeDrive([3; 16]), vec![0; MAX_SEALED_NAME + 1]).await.unwrap() {
            UserResponse::Error { message } => assert!(message.contains("at most"), "{message}"),
            other => panic!("{other:?}"),
        }
        assert_eq!(listed(&ctx, "alice").await.len(), 1);
    }
}
