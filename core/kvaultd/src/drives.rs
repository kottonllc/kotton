// SPDX-License-Identifier: AGPL-3.0-or-later
//! A tenant's drives at this vault: a drive is a tenancy on a vault, and a
//! person may have several, on one vault or many.
//!
//! **What a drive is here: a sealed tree of its own in the tenant's pool.**
//! Each drive is a mount of the tenant's pool made for it, the person's first
//! drive, `personal`, among them (kotton-protocol's *A drive is where things live and
//! a device keeps what its person chose*): a device makes it at the first
//! vault the person enrols, with the same verb as any other, so nothing here
//! sets it apart. The tenancy's own tree, the mount `local`, is the pool's own
//! and no drive; this vault keeps it, lists it, and is never asked to name it:
//!
//! | Tree | Mount (the tree the sealed verbs name) | On the disk | Its name |
//! |---|---|---|---|
//! | the tenancy's own | `local` | `users/<id>/data/` | none: no drive |
//! | each made one | `drive-<32 hex>` (`MadeDrive::tree`) | `users/<id>/drives/<tree>/` | sealed, in `tenant_drives` |
//!
//! On a bucket each is `<prefix>/<id>/<tree>/`, through the same `Shelves`
//! seam the tenancy's own tree rests on. Each tree pins its own key domain at its
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
//! a move's — or refused, never landed in a directory being removed.
//!
//! **One device at a time moves or makes a drive: a lease this vault keeps**
//! (kotton #143). A device takes a lease (`TenantDriveHold`) on every tree a
//! move of it touches here, before it lists or writes it, and holds it to the
//! end; and a device making a drive takes the tenant's *making* lease at one
//! vault, whatever the name. While a tree is held, a write into it
//! ([`write_into`]), a naming of it ([`name`]) and a retire of it ([`retire`])
//! from any other device are refused with `DriveHeld`, which names the holding
//! device by the key this vault admitted it under and says how long the lease
//! has left; a second taker is refused the same way. The holder is not
//! refused. A take waits for the writes in flight into the tree, so a write is
//! either in the tree before the mover lists it, and carried, or refused.
//!
//! - **A retire is fenced by the lease.** One of a tree this vault keeps names
//!   the lease its device holds on it, and is refused when that lease has
//!   lapsed, been let go or been taken by another since, even from the key
//!   that once held it. One of a tree it no longer keeps is `Ok` with or
//!   without a lease, so a retry after a lost answer still reads truly.
//! - **A holder that dies lets go by lapsing.** A lease lasts [`LEASE_FOR`]
//!   unless its holder renews it by its id; a lapsed lease is renewed by no
//!   one and is taken afresh by whoever asks. The clock is this vault's own
//!   monotonic one, so no other party's time is trusted.
//! - **What the vault learns.** That some device of the tenant — the key it
//!   already sees on every request — means to move a tree it already keeps,
//!   or to make a drive, seconds before the listing, the copy and the retire
//!   would tell it so. A lease's id is minted here for each take and forgotten
//!   at its end; leases are kept in memory alone, never written to the
//!   machine db, so a restart forgets them all, and a mover's retire after one
//!   is refused rather than taken on a lease nobody holds any longer.

use crate::peer::PeerContext;
use kotton_common::crypto::kdf_labels;
use kotton_device::users::residency::Residency as _;
use kotton_wire::ipc::{DriveLease, Holding, MadeDrive, TenantDrive, UserResponse, TENANCY_TREE};
use sqlx::{Row as _, SqlitePool};
use std::collections::HashMap;
use std::io;
use std::time::{Duration, Instant};

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

/// How long a lease lasts unless its holder renews it (module doc). A mover
/// renews every third of it, and right before it names a copy finished and
/// before each retire.
pub const LEASE_FOR: Duration = Duration::from_secs(60);

/// One lock per made drive a tenant keeps at this vault, and the leases its
/// devices hold here ([`PeerContext::trees`]; module doc). An entry is made
/// only for a tree this vault keeps, and goes with the tree at its retire, so
/// the maps are as large as the drives kept and the leases held, however many
/// ids requests name.
pub struct Trees {
    locks: std::sync::Mutex<HashMap<(String, String), TreeLock>>,
    leases: std::sync::Mutex<HashMap<(String, Held), Lease>>,
    lasts: Duration,
    /// A test's clock: frozen at `base`, and moved on only by [`Self::pass`],
    /// so no lease test reads the time that really passes.
    #[cfg(test)]
    base: Instant,
    #[cfg(test)]
    passed: std::sync::Mutex<Duration>,
}

impl Default for Trees {
    fn default() -> Self {
        Self::lasting(LEASE_FOR)
    }
}

/// The lock one made drive is held under ([`Trees`]).
type TreeLock = std::sync::Arc<tokio::sync::RwLock<()>>;

/// What a lease is on, as this vault keys it: a tree's own name here, or the
/// tenant's making of a drive.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum Held {
    Tree(String),
    Making,
}

impl From<&Holding> for Held {
    fn from(holding: &Holding) -> Self {
        match holding {
            Holding::Drive(drive) => Self::Tree(drive.tree()),
            Holding::Making => Self::Making,
        }
    }
}

/// One lease: who holds it, by its id, and until when.
#[derive(Debug, Clone)]
struct Lease {
    holder: String,
    id: DriveLease,
    until: Instant,
}

impl Trees {
    /// Leases that last `lasts` unless renewed.
    pub fn lasting(lasts: Duration) -> Self {
        Self {
            locks: Default::default(),
            leases: Default::default(),
            lasts,
            #[cfg(test)]
            base: Instant::now(),
            #[cfg(test)]
            passed: Default::default(),
        }
    }

    fn of(&self, user_id: &str, tree: &str) -> TreeLock {
        let mut held = self.locks.lock().unwrap();
        held.entry((user_id.to_string(), tree.to_string())).or_default().clone()
    }

    /// This vault's monotonic clock; a test's own, frozen, under test.
    #[cfg(not(test))]
    fn now(&self) -> Instant {
        Instant::now()
    }

    #[cfg(test)]
    fn now(&self) -> Instant {
        self.base + *self.passed.lock().unwrap()
    }

    /// Move this vault's lease clock on by `by`, as if that long had passed.
    #[cfg(test)]
    fn pass(&self, by: Duration) {
        *self.passed.lock().unwrap() += by;
    }

    /// The live lease on `held`, if any; a lapsed one is forgotten here.
    fn live(&self, user_id: &str, held: &Held) -> Option<Lease> {
        let now = self.now();
        let mut leases = self.leases.lock().unwrap();
        let key = (user_id.to_string(), held.clone());
        match leases.get(&key) {
            Some(lease) if lease.until > now => Some(lease.clone()),
            Some(_) => {
                leases.remove(&key);
                None
            }
            None => None,
        }
    }

    /// `DriveHeld` when a device other than `caller` holds a live lease on
    /// `held`.
    fn held_against(&self, user_id: &str, held: &Held, caller: &str) -> Option<UserResponse> {
        let lease = self.live(user_id, held)?;
        (lease.holder != caller).then(|| self.held_by(&lease))
    }

    fn held_by(&self, lease: &Lease) -> UserResponse {
        UserResponse::DriveHeld { device_did: lease.holder.clone(), for_secs: secs(lease.until.saturating_duration_since(self.now())) }
    }

    /// Take `held` for `caller`, or renew the lease `renewing` it holds on it.
    fn take(&self, user_id: &str, held: &Held, caller: &str, renewing: Option<DriveLease>) -> UserResponse {
        let now = self.now();
        let mut leases = self.leases.lock().unwrap();
        let key = (user_id.to_string(), held.clone());
        let live = leases.get(&key).filter(|l| l.until > now).cloned();
        if let Some(lease) = live.as_ref().filter(|l| l.holder != caller) {
            return UserResponse::DriveHeld { device_did: lease.holder.clone(), for_secs: secs(lease.until.saturating_duration_since(now)) };
        }
        let id = match (renewing, live) {
            (None, _) => DriveLease(rand::random()),
            (Some(id), Some(lease)) if lease.id == id => id,
            (Some(_), _) => {
                return refused(
                    "the lease named has lapsed, or was let go or taken again since, so it was not renewed; a device \
                     that held it holds nothing it took under it",
                )
            }
        };
        leases.insert(key, Lease { holder: caller.to_string(), id, until: now + self.lasts });
        UserResponse::DriveHold { lease: id, for_secs: secs(self.lasts) }
    }

    /// Let go of `held` when `lease` is the lease on it.
    fn let_go(&self, user_id: &str, held: &Held, lease: DriveLease) {
        let mut leases = self.leases.lock().unwrap();
        let key = (user_id.to_string(), held.clone());
        if leases.get(&key).is_some_and(|l| l.id == lease) {
            leases.remove(&key);
        }
    }

    /// Whether `lease`, said by `caller`, is the live lease on `held`.
    fn fences(&self, user_id: &str, held: &Held, caller: &str, lease: Option<DriveLease>) -> Result<(), Box<UserResponse>> {
        let live = self.live(user_id, held);
        match (live, lease) {
            (Some(l), Some(id)) if l.id == id && l.holder == caller => Ok(()),
            (Some(l), _) if l.holder != caller => Err(Box::new(self.held_by(&l))),
            (_, None) => Err(Box::new(refused(
                "a retire of a drive this vault keeps names the lease the asking device holds on it, and this one \
                 named none, so the drive was not retired",
            ))),
            (_, Some(_)) => Err(Box::new(refused(
                "the lease this retire names has lapsed, or was let go or taken again since, so the drive was not \
                 retired",
            ))),
        }
    }

    /// Forget everything kept for `user_id`'s tree, once it is retired: its
    /// lock and its lease (kotton #155's review: the map grew by one entry per
    /// drive ever made).
    fn forget(&self, user_id: &str, tree: &str) {
        self.locks.lock().unwrap().remove(&(user_id.to_string(), tree.to_string()));
        self.leases.lock().unwrap().remove(&(user_id.to_string(), Held::Tree(tree.to_string())));
    }
}

/// Whole seconds, rounded up, as a lease's answer says them.
fn secs(d: Duration) -> u32 {
    u32::try_from(d.as_millis().div_ceil(1000)).unwrap_or(u32::MAX)
}

/// Hold `user_id`'s drive `mount` for a sealed write into it from `caller`,
/// or refuse the write: a made drive this vault no longer keeps — retired, or
/// never made — and one another device holds a lease on (`DriveHeld`). The
/// tenancy's own tree is never retired or leased, and takes no hold.
pub async fn write_into(
    ctx: &PeerContext,
    user_id: &str,
    mount: &str,
    caller: &str,
) -> Result<Option<tokio::sync::OwnedRwLockReadGuard<()>>, Box<UserResponse>> {
    if MadeDrive::from_tree(mount).is_none() {
        return Ok(None);
    }
    let Some(held) = read_kept(ctx, user_id, mount).await else {
        return Err(Box::new(refused(format!(
            "this vault keeps no drive for '{user_id}' under {mount}: it was retired, or never made here, so the write \
             was refused"
        ))));
    };
    if let Some(theirs) = ctx.trees.held_against(user_id, &Held::Tree(mount.to_string()), caller) {
        return Err(Box::new(theirs));
    }
    Ok(Some(held))
}

/// Whether this vault keeps `user_id`'s tree `tree`.
fn kept(ctx: &PeerContext, user_id: &str, tree: &str) -> bool {
    ctx.pools.get(user_id).is_some_and(|pool| pool.get_remote(tree).is_some())
}

/// `tree`'s lock, held for reading, while this vault keeps the tree; `None`
/// for one it does not, and then no entry is left for it ([`Trees`] holds
/// one per tree kept, and a request naming any other id adds none).
async fn read_kept(ctx: &PeerContext, user_id: &str, tree: &str) -> Option<tokio::sync::OwnedRwLockReadGuard<()>> {
    if !kept(ctx, user_id, tree) {
        return None;
    }
    let held = ctx.trees.of(user_id, tree).read_owned().await;
    if kept(ctx, user_id, tree) {
        return Some(held);
    }
    // Retired while this waited: the retire forgot the entry, and this one's
    // `of` may have made it again.
    drop(held);
    ctx.trees.forget(user_id, tree);
    None
}

/// [`read_kept`], for writing.
async fn write_kept(ctx: &PeerContext, user_id: &str, tree: &str) -> Option<tokio::sync::OwnedRwLockWriteGuard<()>> {
    if !kept(ctx, user_id, tree) {
        return None;
    }
    let held = ctx.trees.of(user_id, tree).write_owned().await;
    if kept(ctx, user_id, tree) {
        return Some(held);
    }
    drop(held);
    ctx.trees.forget(user_id, tree);
    None
}

/// `TenantDriveHold`: take, or renew, a lease for `caller` on what `holding`
/// names (module doc). A take of a tree waits for the writes in flight into
/// it and drops any object still being reassembled there; a tree this vault
/// does not keep is refused.
pub async fn hold(ctx: &PeerContext, user_id: &str, caller: &str, holding: Holding, lease: Option<DriveLease>) -> io::Result<UserResponse> {
    let Some(pool) = ctx.pools.get(user_id) else {
        return Ok(refused(format!("this vault keeps no pool for '{user_id}'")));
    };
    let held = Held::from(&holding);
    let Held::Tree(tree) = &held else {
        return Ok(ctx.trees.take(user_id, &held, caller, lease));
    };
    let unkept = || refused(format!("this vault keeps no drive for '{user_id}' under {tree}, so it holds no lease on one"));
    // A renewal waits for nothing: the writes it would wait for are the
    // holder's own, or were refused since the take.
    if lease.is_some() {
        if pool.get_remote(tree).is_none() {
            return Ok(unkept());
        }
        return Ok(ctx.trees.take(user_id, &held, caller, lease));
    }
    let Some(_writes) = write_kept(ctx, user_id, tree).await else {
        return Ok(unkept());
    };
    let answer = ctx.trees.take(user_id, &held, caller, lease);
    if matches!(answer, UserResponse::DriveHold { .. }) {
        // A write whose first parts came before the take is refused at its
        // next part; what it left being reassembled goes now.
        let reassembling = format!("sealed:{tree}");
        ctx.reassembly.lock().await.retain(|(user, slot, _, _), _| !(user == user_id && *slot == reassembling));
    }
    Ok(answer)
}

/// `TenantDriveLetGo`: let go of `lease` on what `holding` names, if it is
/// still the lease there. Always `Ok`.
pub fn let_go(ctx: &PeerContext, user_id: &str, holding: Holding, lease: DriveLease) -> UserResponse {
    ctx.trees.let_go(user_id, &Held::from(&holding), lease);
    UserResponse::Ok
}

/// `TenantDriveMake`: a sealed tree of its own for `user_id`, under `drive`,
/// with `sealed_name` kept beside it.
///
/// The row first, in a transaction, then the tree: a tree that cannot be made
/// rolls the row back, and a row that cannot be committed takes the tree out
/// again, so a drive is listed with its name or not at all. The tree is made
/// held by `caller`, and the answer is its lease (module doc): a move copies
/// into the tree under it, and a create lets it go.
pub async fn make(ctx: &PeerContext, user_id: &str, caller: &str, drive: MadeDrive, sealed_name: Vec<u8>) -> io::Result<UserResponse> {
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
    Ok(ctx.trees.take(user_id, &Held::Tree(tree), caller, None))
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
    trees.sort_by_key(|t| (t != TENANCY_TREE, t.clone()));
    let mut drives = Vec::with_capacity(trees.len());
    for tree in trees {
        // A mount of the pool that is neither the tenancy's own tree nor a made one is
        // nothing a tenant's verb made, and is not one of their drives.
        if tree != TENANCY_TREE && MadeDrive::from_tree(&tree).is_none() {
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
/// how a move names its tree finished once the copy is verified. Refused with
/// `DriveHeld` while another device holds the tree (module doc).
pub async fn name(ctx: &PeerContext, user_id: &str, caller: &str, drive: MadeDrive, sealed_name: Vec<u8>) -> io::Result<UserResponse> {
    if sealed_name.len() > MAX_SEALED_NAME {
        return Ok(refused(format!(
            "a drive's sealed name is at most {MAX_SEALED_NAME} bytes; this one is {}",
            sealed_name.len()
        )));
    }
    let tree = drive.tree();
    // Held for reading, as a write is, so a take or a retire waits for it and
    // it reads the lease as the take left it.
    let Some(_naming) = read_kept(ctx, user_id, &tree).await else {
        return Ok(refused(format!("this vault keeps no drive for '{user_id}' under {tree}")));
    };
    if let Some(theirs) = ctx.trees.held_against(user_id, &Held::Tree(tree.clone()), caller) {
        return Ok(theirs);
    }
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
/// has just retired is, so a retry after a lost answer is read truly. One it
/// keeps is retired only under `lease`, the live lease `caller` holds on it
/// (module doc, a fencing token); and once it is gone, its lock and lease go.
///
/// A key the tree's listing holds that is not canonical — `x\y` on a disk,
/// `../x` in a bucket — is refused by the walk, not deleted by key, and goes with the tree's directory
/// (`crate::tenancy`, "The walk admits its listing"). How many were refused is
/// in this vault's log: the answer is `UserResponse::Ok`, which carries no
/// count (kotton #310). The device that asked has counted the same keys at its
/// own admission of the listing, when it was a move.
pub async fn retire(ctx: &PeerContext, user_id: &str, caller: &str, drive: MadeDrive, lease: Option<DriveLease>) -> io::Result<UserResponse> {
    let Some(pool) = ctx.pools.get(user_id) else {
        return Ok(refused(format!("this vault keeps no pool for '{user_id}'")));
    };
    let tree = drive.tree();
    // Every write into the drive in flight finishes first, and none starts
    // until the tree is gone ([`Trees`]); a write still being reassembled is
    // dropped, so its next part finds no tree and is refused.
    let _retiring = ctx.trees.of(user_id, &tree).write_owned().await;
    let path = pool.shelf_mounts().into_iter().find(|(m, _)| *m == tree).map(|(_, p)| p);
    if path.is_some() {
        if let Err(refusal) = ctx.trees.fences(user_id, &Held::Tree(tree.clone()), caller, lease) {
            return Ok(*refusal);
        }
    }
    let reassembling = format!("sealed:{tree}");
    ctx.reassembly.lock().await.retain(|(user, slot, _, _), _| !(user == user_id && *slot == reassembling));
    let Some(path) = path else {
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
        ctx.trees.forget(user_id, &tree);
        return Ok(UserResponse::Ok);
    };
    let shelf = ctx.runtime.shelves().open(user_id, &tree, &path);
    let cleared = crate::tenancy::clear_shelf(shelf.as_ref()).await?;
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
    let keys_refused = cleared.refused.len();
    if keys_refused > 0 && crate::tenancy::left_on(shelf.as_ref()).await {
        tracing::warn!(user_id, tree, keys_refused, "a retired drive's shelf still holds objects whose keys are not storage keys; nothing at the shelf seam removes them by prefix");
    }
    ctx.meter.set(user_id, crate::peer::measure_pool(&pool).await);
    ctx.trees.forget(user_id, &tree);
    tracing::info!(user_id, tree, objects = cleared.removed, keys_refused, "retired a tenant's drive");
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

    /// The device that makes and moves drives in these tests, by its key.
    const DEVICE: &str = "did:key:zdevice";

    /// Make `drive` for `user` as [`DEVICE`], and the lease it then holds.
    async fn made(ctx: &PeerContext, user: &str, drive: MadeDrive, sealed_name: Vec<u8>) -> DriveLease {
        match make(ctx, user, DEVICE, drive, sealed_name).await.unwrap() {
            UserResponse::DriveHold { lease, for_secs } => {
                assert_eq!(for_secs, 60, "a lease lasts a minute");
                lease
            }
            other => panic!("the drive was not made: {other:?}"),
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
        ctx.pools.get(user).unwrap().list_sealed(tree, None).await.unwrap().into_iter().map(|(k, _, _)| k).collect()
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
        let _photos_lease = made(&ctx, "alice", photos, b"sealed photos".to_vec()).await;
        let work_lease = made(&ctx, "alice", work, b"sealed work".to_vec()).await;
        match make(&ctx, "alice", DEVICE, photos, vec![]).await.unwrap() {
            UserResponse::Error { message } => assert!(message.contains("already keeps"), "{message}"),
            other => panic!("one id was made twice: {other:?}"),
        }

        write(&ctx, "alice", TENANCY_TREE, "x/first", b"first").await;
        write(&ctx, "alice", &photos.tree(), "x/photo", b"a photo").await;
        write(&ctx, "alice", &work.tree(), "x/memo", b"memo").await;
        assert_eq!(keys(&ctx, "alice", TENANCY_TREE).await, ["x/first"]);
        assert_eq!(keys(&ctx, "alice", &photos.tree()).await, ["x/photo"]);
        assert_eq!(keys(&ctx, "alice", &work.tree()).await, ["x/memo"]);

        let drives = listed(&ctx, "alice").await;
        let said: Vec<(String, Vec<u8>)> = drives.iter().map(|d| (d.tree.clone(), d.sealed_name.clone())).collect();
        assert_eq!(
            said,
            [
                (TENANCY_TREE.to_string(), vec![]),
                (photos.tree(), b"sealed photos".to_vec()),
                (work.tree(), b"sealed work".to_vec()),
            ]
        );
        assert!(drives.iter().all(|d| d.held > 0), "{drives:?}");
        assert_eq!(listed(&ctx, "bob").await.len(), 1, "bob has his first drive alone");
        assert!(dir.path().join("vault/users/alice/drives").join(photos.tree()).is_dir());

        assert!(matches!(retire(&ctx, "alice", DEVICE, work, Some(work_lease)).await.unwrap(), UserResponse::Ok));
        assert_eq!(listed(&ctx, "alice").await.iter().map(|d| d.tree.clone()).collect::<Vec<_>>(), [TENANCY_TREE.to_string(), photos.tree()]);
        assert!(!dir.path().join("vault/users/alice/drives").join(work.tree()).exists(), "the retired tree is on the disk");
        assert_eq!(keys(&ctx, "alice", &photos.tree()).await, ["x/photo"], "retiring one drive touched another");
        assert_eq!(keys(&ctx, "alice", TENANCY_TREE).await, ["x/first"]);
        assert_eq!(
            ctx.meter.held("alice"),
            Some(listed(&ctx, "alice").await.iter().map(|d| d.held).sum::<u64>()),
            "the meter counts what is left, over every drive"
        );
        assert!(matches!(name(&ctx, "alice", DEVICE, photos, b"named again".to_vec()).await.unwrap(), UserResponse::Ok));
        assert_eq!(listed(&ctx, "alice").await[1].sealed_name, b"named again");
        match name(&ctx, "alice", DEVICE, work, b"x".to_vec()).await.unwrap() {
            UserResponse::Error { message } => assert!(message.contains("keeps no drive"), "{message}"),
            other => panic!("a retired drive was named: {other:?}"),
        }
        match name(&ctx, "bob", DEVICE, photos, b"x".to_vec()).await.unwrap() {
            UserResponse::Error { message } => assert!(message.contains("keeps no drive"), "{message}"),
            other => panic!("bob named alice's drive: {other:?}"),
        }
        // Idempotent: asked again — an answer lost, a retry — it is `Ok`, and
        // nothing else changes.
        assert!(
            matches!(retire(&ctx, "alice", DEVICE, work, None).await.unwrap(), UserResponse::Ok),
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
        let lease = made(&ctx, "alice", photos, b"sealed".to_vec()).await;
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
        let held = write_into(&ctx, "alice", &photos.tree(), DEVICE).await.expect("a kept drive takes the write");
        assert!(matches!(part(0).await, UserResponse::Ok), "the first part is taken");
        let retiring = tokio::spawn({
            let ctx = Arc::clone(&ctx);
            async move { retire(&ctx, "alice", DEVICE, photos, Some(lease)).await.unwrap() }
        });
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        assert!(!retiring.is_finished(), "the retire did not wait for the write in flight");
        drop(held);
        assert!(matches!(retiring.await.unwrap(), UserResponse::Ok));

        // The last part comes after the retire: refused, by name.
        match write_into(&ctx, "alice", &photos.tree(), DEVICE).await {
            Err(refusal) => match *refusal {
                UserResponse::Error { message } => assert!(message.contains("keeps no drive") && message.contains("refused"), "{message}"),
                other => panic!("{other:?}"),
            },
            other => panic!("a write into a retired drive was let in: {:?}", other.map(|_| ())),
        }
        assert!(ctx.reassembly.lock().await.is_empty(), "the retired drive's part was kept");
        assert!(!dir.path().join("vault/users/alice/drives").join(photos.tree()).exists(), "the retired tree is on the disk");
        assert!(write_into(&ctx, "alice", TENANCY_TREE, DEVICE).await.unwrap().is_none(), "the first drive took a hold");
    }

    /// Two of alice's devices, by their keys, besides [`DEVICE`].
    const A: &str = "did:key:za";
    const B: &str = "did:key:zb";

    async fn take(ctx: &PeerContext, caller: &str, holding: Holding, lease: Option<DriveLease>) -> UserResponse {
        hold(ctx, "alice", caller, holding, lease).await.unwrap()
    }

    fn the_lease(answer: UserResponse) -> DriveLease {
        match answer {
            UserResponse::DriveHold { lease, .. } => lease,
            other => panic!("no lease was given: {other:?}"),
        }
    }

    fn held_by(answer: &UserResponse, holder: &str) {
        match answer {
            UserResponse::DriveHeld { device_did, for_secs } => {
                assert_eq!(device_did, holder, "the refusal names another holder");
                assert!(*for_secs > 0 && *for_secs <= 60, "{for_secs}");
            }
            other => panic!("not refused as held by {holder}: {other:?}"),
        }
    }

    fn refused_saying(answer: &UserResponse, words: &str) {
        match answer {
            UserResponse::Error { message } => assert!(message.contains(words), "{message}"),
            other => panic!("not refused ({words}): {other:?}"),
        }
    }

    /// **A lease refuses every other device and not its holder** (kotton
    /// #143). While A holds alice's drive, B's take, write, naming and retire
    /// are each refused with `DriveHeld`, naming A and the time left; A's
    /// write and naming are let in. A taking it again is a new lease, and the
    /// one it supersedes renews nothing and retires nothing: it is a fencing
    /// token. Let go, B takes it at once.
    #[tokio::test]
    async fn a_lease_refuses_every_other_device_and_not_its_holder() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = a_vault(dir.path()).await;
        let photos = MadeDrive([8; 16]);
        let made_under = made(&ctx, "alice", photos, b"sealed".to_vec()).await;
        assert!(matches!(let_go(&ctx, "alice", Holding::Drive(photos), made_under), UserResponse::Ok));
        let first = the_lease(take(&ctx, A, Holding::Drive(photos), None).await);

        held_by(&take(&ctx, B, Holding::Drive(photos), None).await, A);
        match write_into(&ctx, "alice", &photos.tree(), B).await {
            Err(refusal) => held_by(&refusal, A),
            Ok(_) => panic!("B wrote into a drive A holds"),
        }
        held_by(&name(&ctx, "alice", B, photos, b"x".to_vec()).await.unwrap(), A);
        held_by(&retire(&ctx, "alice", B, photos, None).await.unwrap(), A);
        held_by(&retire(&ctx, "alice", B, photos, Some(first)).await.unwrap(), A);
        assert!(write_into(&ctx, "alice", &photos.tree(), A).await.unwrap().is_some(), "the holder's write was refused");
        assert!(matches!(name(&ctx, "alice", A, photos, b"named".to_vec()).await.unwrap(), UserResponse::Ok));

        let again = the_lease(take(&ctx, A, Holding::Drive(photos), None).await);
        assert_ne!(again, first, "a take is a fresh lease");
        refused_saying(&take(&ctx, A, Holding::Drive(photos), Some(first)).await, "not renewed");
        refused_saying(&retire(&ctx, "alice", A, photos, Some(first)).await.unwrap(), "not retired");
        refused_saying(&retire(&ctx, "alice", A, photos, None).await.unwrap(), "named none");
        assert_eq!(the_lease(take(&ctx, A, Holding::Drive(photos), Some(again)).await), again, "the live lease renews");
        assert_eq!(listed(&ctx, "alice").await.len(), 2, "a refused retire took the drive");

        assert!(matches!(let_go(&ctx, "alice", Holding::Drive(photos), first), UserResponse::Ok));
        held_by(&take(&ctx, B, Holding::Drive(photos), None).await, A);
        assert!(matches!(let_go(&ctx, "alice", Holding::Drive(photos), again), UserResponse::Ok));
        let bs = the_lease(take(&ctx, B, Holding::Drive(photos), None).await);
        assert!(matches!(retire(&ctx, "alice", B, photos, Some(bs)).await.unwrap(), UserResponse::Ok));
    }

    /// **A holder that dies lets go by lapsing, and a retire after is fenced**
    /// (kotton #143). A's lease outlives its minute unrenewed; B takes the
    /// drive; A's renewal and A's retire under its old lease are refused, both
    /// while B holds it and after B lets go, so A's move stops and retires
    /// nothing a pass may since have written into. B retires under its own,
    /// and the vault forgets the tree's lock and lease with it; a retire asked
    /// again, with no lease, is `Ok`. A tree the vault does not keep takes no
    /// lease. No clock is waited on: the vault's lease clock is moved on.
    #[tokio::test]
    async fn a_lease_that_lapses_is_taken_by_another_and_fences_the_first_holders_retire() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = a_vault(dir.path()).await;
        let photos = MadeDrive([9; 16]);
        let a = made(&ctx, "alice", photos, b"sealed".to_vec()).await;
        ctx.trees.pass(Duration::from_secs(59));
        held_by(&take(&ctx, B, Holding::Drive(photos), None).await, DEVICE);
        ctx.trees.pass(Duration::from_secs(2));
        let b = the_lease(take(&ctx, B, Holding::Drive(photos), None).await);

        held_by(&take(&ctx, DEVICE, Holding::Drive(photos), Some(a)).await, B);
        held_by(&retire(&ctx, "alice", DEVICE, photos, Some(a)).await.unwrap(), B);
        assert!(matches!(let_go(&ctx, "alice", Holding::Drive(photos), b), UserResponse::Ok));
        refused_saying(&take(&ctx, DEVICE, Holding::Drive(photos), Some(a)).await, "not renewed");
        refused_saying(&retire(&ctx, "alice", DEVICE, photos, Some(a)).await.unwrap(), "lapsed");
        assert_eq!(listed(&ctx, "alice").await.len(), 2, "a fenced retire took the drive");

        let b = the_lease(take(&ctx, B, Holding::Drive(photos), None).await);
        assert!(matches!(retire(&ctx, "alice", B, photos, Some(b)).await.unwrap(), UserResponse::Ok));
        assert_eq!(listed(&ctx, "alice").await.len(), 1);
        let key = ("alice".to_string(), photos.tree());
        assert!(!ctx.trees.locks.lock().unwrap().contains_key(&key), "the retired tree's lock was kept");
        assert!(ctx.trees.live("alice", &Held::Tree(photos.tree())).is_none(), "the retired tree's lease was kept");
        assert!(matches!(retire(&ctx, "alice", A, photos, None).await.unwrap(), UserResponse::Ok), "a retire asked again is not Ok");
        refused_saying(&take(&ctx, A, Holding::Drive(photos), None).await, "keeps no drive");
    }

    /// **The making lease is one per tenant, whatever the name** (kotton
    /// #143): while A holds it, B is refused, naming A; bob's is his own; let
    /// go, B takes it.
    #[tokio::test]
    async fn one_device_at_a_time_holds_the_making_of_a_drive() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = a_vault(dir.path()).await;
        let a = the_lease(take(&ctx, A, Holding::Making, None).await);
        held_by(&take(&ctx, B, Holding::Making, None).await, A);
        assert!(matches!(hold(&ctx, "bob", B, Holding::Making, None).await.unwrap(), UserResponse::DriveHold { .. }), "bob's making is alice's");
        let_go(&ctx, "alice", Holding::Making, a);
        assert!(matches!(take(&ctx, B, Holding::Making, None).await, UserResponse::DriveHold { .. }));
    }

    /// **A take waits for the writes in flight into the tree** (kotton #143),
    /// and drops what one left being reassembled: a write is either in the
    /// tree before the mover lists it, or refused.
    #[tokio::test]
    async fn a_take_waits_for_a_write_in_flight_and_drops_its_parts() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = a_vault(dir.path()).await;
        let photos = MadeDrive([10; 16]);
        let made_under = made(&ctx, "alice", photos, b"sealed".to_vec()).await;
        let_go(&ctx, "alice", Holding::Drive(photos), made_under);
        let writing = write_into(&ctx, "alice", &photos.tree(), B).await.unwrap();
        let body = vec![7u8; 64];
        let host = VaultHost { runtime: &ctx.runtime, pools: &ctx.pools };
        let part = kotton_device::users::files::write_sealed(
            &host,
            "alice".into(),
            photos.tree(),
            "x/photo".into(),
            body[..32].to_vec(),
            "domain".into(),
            0,
            body.len() as u64,
            blake3::hash(&body).to_hex().to_string(),
            Some(&ctx.reassembly),
        )
        .await
        .unwrap();
        assert!(matches!(part, UserResponse::Ok));
        let mut taking = Box::pin(take(&ctx, A, Holding::Drive(photos), None));
        tokio::select! {
            biased;
            answer = &mut taking => panic!("the take did not wait for the write in flight: {answer:?}"),
            _ = std::future::ready(()) => {}
        }
        drop(writing);
        let lease = the_lease(taking.await);
        assert!(ctx.reassembly.lock().await.is_empty(), "the write's first part outlived the take");
        match write_into(&ctx, "alice", &photos.tree(), B).await {
            Err(refusal) => held_by(&refusal, A),
            Ok(_) => panic!("the write's next part was let in"),
        }

        // A renewal waits for nothing: with the holder's own write in flight,
        // it is answered at its first poll.
        let _holders = write_into(&ctx, "alice", &photos.tree(), A).await.unwrap();
        let mut renewing = Box::pin(take(&ctx, A, Holding::Drive(photos), Some(lease)));
        tokio::select! {
            biased;
            answer = &mut renewing => assert_eq!(the_lease(answer), lease),
            _ = std::future::ready(()) => panic!("a renewal waited behind a write in flight"),
        }
    }

    /// **A request naming a tree the vault does not keep leaves nothing
    /// behind** (kotton #143; #155's review). A write into, a naming of, a
    /// take of, a renewal on and a retire of a made drive's id this vault
    /// never made are each refused or answered, and its lock and lease maps
    /// hold no entry for that id afterwards; nor for a drive once retired.
    #[tokio::test]
    async fn a_request_naming_a_tree_not_kept_leaves_no_entry() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = a_vault(dir.path()).await;
        let never = MadeDrive([11; 16]);
        assert!(write_into(&ctx, "alice", &never.tree(), A).await.is_err());
        refused_saying(&name(&ctx, "alice", A, never, b"x".to_vec()).await.unwrap(), "keeps no drive");
        refused_saying(&take(&ctx, A, Holding::Drive(never), None).await, "keeps no drive");
        refused_saying(&take(&ctx, A, Holding::Drive(never), Some(DriveLease([1; 16]))).await, "keeps no drive");
        assert!(matches!(retire(&ctx, "alice", A, never, None).await.unwrap(), UserResponse::Ok));
        let photos = MadeDrive([12; 16]);
        let lease = made(&ctx, "alice", photos, b"sealed".to_vec()).await;
        drop(write_into(&ctx, "alice", &photos.tree(), DEVICE).await.unwrap());
        assert!(matches!(retire(&ctx, "alice", DEVICE, photos, Some(lease)).await.unwrap(), UserResponse::Ok));
        assert!(write_into(&ctx, "alice", &photos.tree(), DEVICE).await.is_err());
        assert!(ctx.trees.locks.lock().unwrap().is_empty(), "an entry was left for a tree not kept");
        assert!(ctx.trees.leases.lock().unwrap().is_empty(), "a lease was left for a tree not kept");
    }

    /// A sealed name past the bound is refused, and no tree is made for it.
    #[tokio::test]
    async fn a_sealed_name_past_the_bound_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = a_vault(dir.path()).await;
        match make(&ctx, "alice", DEVICE, MadeDrive([3; 16]), vec![0; MAX_SEALED_NAME + 1]).await.unwrap() {
            UserResponse::Error { message } => assert!(message.contains("at most"), "{message}"),
            other => panic!("{other:?}"),
        }
        assert_eq!(listed(&ctx, "alice").await.len(), 1);
    }

    /// Where `tree` of `user`'s pool rests on the disk.
    fn tree_dir(ctx: &PeerContext, user: &str, tree: &str) -> std::path::PathBuf {
        let pool = ctx.pools.get(user).unwrap();
        pool.shelf_mounts().into_iter().find(|(t, _)| t == tree).expect("the tree rests on a directory").1
    }

    /// Each event the vault logs on this thread while the guard lives, as its
    /// fields' debug text, `message` among them. A retire answers `Ok` and a
    /// drop its readout, neither with a count: what the walk refused is in the
    /// log, its warning per key and the count on the summary line, and this is
    /// how a test reads it there.
    #[derive(Clone, Default)]
    struct Logged(Arc<std::sync::Mutex<Vec<std::collections::BTreeMap<String, String>>>>);

    impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for Logged {
        fn on_event(&self, event: &tracing::Event<'_>, _: tracing_subscriber::layer::Context<'_, S>) {
            struct Fields(std::collections::BTreeMap<String, String>);
            impl tracing::field::Visit for Fields {
                fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                    self.0.insert(field.name().to_string(), format!("{value:?}"));
                }
            }
            let mut fields = Fields(Default::default());
            event.record(&mut fields);
            self.0.lock().unwrap().push(fields.0);
        }
    }

    impl Logged {
        fn start() -> (Self, tracing::subscriber::DefaultGuard) {
            use tracing_subscriber::layer::SubscriberExt as _;
            let logged = Self::default();
            let guard = tracing::subscriber::set_default(tracing_subscriber::registry().with(logged.clone()));
            (logged, guard)
        }

        /// The keys the walk logged it refused, as their debug text.
        fn refused(&self) -> Vec<String> {
            self.0
                .lock()
                .unwrap()
                .iter()
                .filter(|e| e.get("message").is_some_and(|m| m.contains("the walk refused it")))
                .filter_map(|e| e.get("key").cloned())
                .collect()
        }

        /// `field` on the event whose message is `message`.
        fn field(&self, message: &str, field: &str) -> Option<String> {
            self.0
                .lock()
                .unwrap()
                .iter()
                .find(|e| e.get("message").is_some_and(|m| m == message))
                .and_then(|e| e.get(field).cloned())
        }
    }

    /// What [`plant_what_no_device_wrote`] put in a tree's directory.
    struct Planted {
        /// `x%5Cy`: in the store's encoding, so the shelf lists it, as `x\y`,
        /// which is not a storage key.
        refused: std::path::PathBuf,
        /// `..%2Fx` and `a%zz`: names the store's encoding never writes, so
        /// the shelf lists neither (kotton #349). The first once listed as
        /// `../x`, a path outside the tree; the second as `a%zz`, a key that
        /// resolves to another name.
        unlisted: [std::path::PathBuf; 2],
        /// `x`, beside the tree, where a delete of `../x` would land.
        beside: std::path::PathBuf,
    }

    /// Plant, in `tree`'s directory, files no device wrote: one the shelf
    /// lists under a key that is not canonical, and two it does not list at
    /// all; and a file `x` beside the tree.
    async fn plant_what_no_device_wrote(ctx: &PeerContext, user: &str, tree: &str) -> Planted {
        let dir = tree_dir(ctx, user, tree);
        std::fs::create_dir_all(&dir).unwrap();
        let planted = Planted {
            refused: dir.join("x%5Cy"),
            unlisted: [dir.join("..%2Fx"), dir.join("a%zz")],
            beside: dir.parent().unwrap().join("x"),
        };
        for file in [&planted.refused, &planted.unlisted[0], &planted.unlisted[1]] {
            std::fs::write(file, b"served").unwrap();
        }
        std::fs::write(&planted.beside, b"beside the tree").unwrap();
        let shelf = ctx.runtime.shelves().open(user, tree, &dir);
        let listed: Vec<String> = shelf.list(std::path::Path::new("")).await.unwrap().into_iter().map(|e| e.key).collect();
        assert!(listed.iter().any(|k| k == "x\\y"), "the shelf lists `x\\y`: {listed:?}");
        assert!(!listed.iter().any(|k| k == "../x" || k.starts_with("a%")), "the shelf lists a name the store never writes: {listed:?}");
        planted
    }

    /// **A retire takes a tree whose listing holds a key that is not
    /// canonical** (kotton #310). The tree's shelf lists `x\y`; the retire's
    /// walk admits each listed key, refuses that one rather than asking the
    /// store to delete it, deletes every canonical object, and the tree's
    /// directory goes whole, the refused file with it. Every other drive is
    /// untouched. The refusal is read in the retire's log, so the test fails
    /// if the walk deletes `x\y` by key instead: that delete would succeed.
    ///
    /// The tree also holds `..%2Fx` and `a%zz`, names the store never writes
    /// (kotton #349). Its listing names neither, so the walk neither asks to
    /// delete `../x`, outside the tree, nor deletes `a%zz` by a key that
    /// resolves elsewhere and fails on it; both go with the directory, and
    /// the `x` beside the tree is still there.
    #[tokio::test]
    async fn a_retire_takes_a_tree_whose_listing_holds_a_key_that_is_not_canonical() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = a_vault(dir.path()).await;
        let photos = MadeDrive([5; 16]);
        let lease = made(&ctx, "alice", photos, b"sealed".to_vec()).await;
        write(&ctx, "alice", TENANCY_TREE, "x/first", b"first").await;
        write(&ctx, "alice", &photos.tree(), "x/photo", b"a photo").await;
        let tree = tree_dir(&ctx, "alice", &photos.tree());
        let planted = plant_what_no_device_wrote(&ctx, "alice", &photos.tree()).await;

        let (logged, _logging) = Logged::start();
        let answer = retire(&ctx, "alice", DEVICE, photos, Some(lease)).await;
        assert!(matches!(answer, Ok(UserResponse::Ok)), "the retire refused the tree: {answer:?}");
        assert_eq!(logged.refused(), [r#""x\\y""#], "the retire's walk did not refuse `x\\y`");
        assert_eq!(logged.field("retired a tenant's drive", "keys_refused").as_deref(), Some("1"), "the retire did not count the refusal");
        for file in &planted.unlisted {
            assert!(!file.exists(), "{file:?}, which no listing names, outlived the retire");
        }
        assert!(!tree.exists(), "the retired tree, or the file it refused, is on the disk");
        assert_eq!(std::fs::read(&planted.beside).unwrap(), b"beside the tree", "the retire reached outside the tree");
        assert_eq!(listed(&ctx, "alice").await.iter().map(|d| d.tree.clone()).collect::<Vec<_>>(), [TENANCY_TREE]);
        assert_eq!(keys(&ctx, "alice", TENANCY_TREE).await, ["x/first"], "the retire touched another drive");
    }

    /// **The walk counts what it refused, and deletes it by no key.** On the
    /// tree's own shelf, the walk deletes the one canonical object, returns
    /// `x\y` as refused, and leaves the refused file where it rests for the
    /// directory removal to take. What the shelf does not list (`..%2Fx`,
    /// `a%zz`, kotton #349) the walk neither refuses nor counts nor deletes:
    /// it rests for the same removal. The `x` beside the tree is untouched.
    #[tokio::test]
    async fn the_walk_refuses_a_listed_key_that_is_not_canonical_and_counts_it() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = a_vault(dir.path()).await;
        let photos = MadeDrive([7; 16]);
        made(&ctx, "alice", photos, b"sealed".to_vec()).await;
        write(&ctx, "alice", &photos.tree(), "x/photo", b"a photo").await;
        let tree = tree_dir(&ctx, "alice", &photos.tree());
        let planted = plant_what_no_device_wrote(&ctx, "alice", &photos.tree()).await;
        let shelf = ctx.runtime.shelves().open("alice", &photos.tree(), &tree);

        let cleared = crate::tenancy::clear_shelf(shelf.as_ref()).await.expect("the walk refused the shelf");
        assert_eq!(cleared.removed, 1, "the canonical object was not deleted: {cleared:?}");
        assert_eq!(cleared.refused.iter().map(|r| r.key.as_str()).collect::<Vec<_>>(), ["x\\y"]);
        assert!(planted.refused.exists(), "the refused file was deleted by its key");
        for file in &planted.unlisted {
            assert!(file.exists(), "the walk deleted {file:?}, which the shelf does not list");
        }
        assert_eq!(std::fs::read(&planted.beside).unwrap(), b"beside the tree");
        assert!(crate::tenancy::left_on(shelf.as_ref()).await, "the shelf does not list the refused file");
        kotton_common::fs::remove_dir_all_retrying(&tree).unwrap();
        assert!(!crate::tenancy::left_on(shelf.as_ref()).await, "the directory removal left something listed");
    }

    /// **A drop takes a pool whose listings hold a key that is not canonical**
    /// (kotton #310). Alice's first drive and a made one each list `x\y`; the
    /// drop's walk refuses it in each, empties the rest, and her directory goes
    /// whole, with it the `..%2Fx` and `a%zz` each tree holds and no listing
    /// names (kotton #349). Bob, on the same vault, keeps all of his. The
    /// refusals are read in the drop's log, so the test fails if the walk
    /// deletes `x\y` by key instead: that delete would succeed.
    #[tokio::test]
    async fn a_drop_takes_a_pool_whose_listings_hold_a_key_that_is_not_canonical() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = a_vault(dir.path()).await;
        crate::meter::init(&ctx.db).await.unwrap();
        crate::doors::init(&ctx.db).await.unwrap();
        crate::carry::init(&ctx.db).await.unwrap();
        let photos = MadeDrive([6; 16]);
        made(&ctx, "alice", photos, b"sealed".to_vec()).await;
        write(&ctx, "alice", TENANCY_TREE, "x/first", b"first").await;
        write(&ctx, "alice", &photos.tree(), "x/photo", b"a photo").await;
        write(&ctx, "bob", TENANCY_TREE, "x/bobs", b"bob's").await;
        let first = plant_what_no_device_wrote(&ctx, "alice", TENANCY_TREE).await;
        let made = plant_what_no_device_wrote(&ctx, "alice", &photos.tree()).await;

        let sessions = kotton_session::service::tokens::SessionMap::default();
        let (logged, _logging) = Logged::start();
        let dropped = crate::tenancy::drop_tenant(&ctx, &sessions, "alice").await;
        assert!(dropped.is_ok(), "the drop refused the pool: {:?}", dropped.err());
        assert_eq!(logged.refused(), [r#""x\\y""#; 2], "the drop's walk did not refuse `x\\y` in each tree");
        assert_eq!(logged.field("dropped a tenant", "keys_refused").as_deref(), Some("2"), "the drop did not count the refusals");
        for file in first.unlisted.iter().chain(&made.unlisted) {
            assert!(!file.exists(), "{file:?}, which no listing names, outlived the drop");
        }
        assert!(!dir.path().join("vault/users/alice").exists(), "alice's directory is on the disk");
        assert!(ctx.pools.get("alice").is_none());
        assert_eq!(keys(&ctx, "bob", TENANCY_TREE).await, ["x/bobs"], "the drop touched bob's pool");
    }

    /// **A name the vault keeps only a number for is dropped** (kotton #430).
    /// Priya was invited with a quota and never joined: the vault keeps a
    /// `pool_quotas` row for her and nothing else, no pool and no shelf. The
    /// drop takes the row and answers her readout. It walks no shelf for her,
    /// since no pool made one: a walk of `users/priya/data` would be refused
    /// by the missing root (kotton #412), and rightly. Alice's and Bob's
    /// pools are untouched.
    #[tokio::test]
    async fn a_name_kept_only_by_its_quota_is_dropped_without_walking_a_shelf_no_pool_made() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = a_vault(dir.path()).await;
        crate::meter::init(&ctx.db).await.unwrap();
        crate::doors::init(&ctx.db).await.unwrap();
        crate::carry::init(&ctx.db).await.unwrap();
        ctx.meter.set_pool_quota(&ctx.db, "priya", 1 << 20).await.unwrap();
        write(&ctx, "alice", TENANCY_TREE, "x/alices", b"alice's").await;
        assert!(crate::tenancy::names(&ctx).await.unwrap().contains("priya"), "the vault does not keep priya's number");
        assert!(!dir.path().join("vault/users/priya").exists(), "an invite made priya a directory");

        let sessions = kotton_session::service::tokens::SessionMap::default();
        let (logged, _logging) = Logged::start();
        let dropped = crate::tenancy::drop_tenant(&ctx, &sessions, "priya")
            .await
            .unwrap_or_else(|e| panic!("the drop refused a name kept only by its quota: {e}"));
        assert_eq!((dropped.user_id.as_str(), dropped.quota, dropped.held), ("priya", Some(1 << 20), 0));
        assert_eq!(logged.field("dropped a tenant", "objects").as_deref(), Some("0"));
        assert!(!crate::tenancy::names(&ctx).await.unwrap().contains("priya"), "the drop left priya's number");
        assert!(!dir.path().join("vault/users/priya").exists(), "the drop made priya a directory");
        assert_eq!(keys(&ctx, "alice", TENANCY_TREE).await, ["x/alices"], "the drop touched alice's pool");
        assert!(ctx.pools.get("bob").is_some(), "the drop took bob's pool");
    }

    /// **A pool that is not resident is walked where its configuration says it
    /// rests** (kotton #430). Alice's pool holds an object and is taken out of
    /// residency, as a vault that could not load it would have it; her
    /// `config.toml` still names her mount. The drop walks that shelf, deletes
    /// the object, and her directory goes.
    #[tokio::test]
    async fn a_pool_not_resident_is_walked_where_its_configuration_says_it_rests() {
        let dir = tempfile::tempdir().unwrap();
        let ctx = a_vault(dir.path()).await;
        crate::meter::init(&ctx.db).await.unwrap();
        crate::doors::init(&ctx.db).await.unwrap();
        crate::carry::init(&ctx.db).await.unwrap();
        write(&ctx, "alice", TENANCY_TREE, "x/alices", b"alice's").await;
        assert!(ctx.pools.remove("alice"));

        let sessions = kotton_session::service::tokens::SessionMap::default();
        let (logged, _logging) = Logged::start();
        let dropped = crate::tenancy::drop_tenant(&ctx, &sessions, "alice").await;
        assert!(dropped.is_ok(), "the drop refused a pool that is not resident: {:?}", dropped.err());
        assert_eq!(logged.field("dropped a tenant", "objects").as_deref(), Some("1"), "the drop did not walk alice's shelf");
        assert!(!dir.path().join("vault/users/alice").exists(), "alice's directory is on the disk");
        assert!(ctx.pools.get("bob").is_some(), "the drop took bob's pool");
    }
}
