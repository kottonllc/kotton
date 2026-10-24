// SPDX-License-Identifier: AGPL-3.0-or-later
//! The drive's verbs on a person's device: `drive
//! create <name> [--on <vault>]`, `list`, `show <name>` and `move <name> --to
//! <vault>`, over the several drives a person may keep on one vault or many.
//!
//! **A drive is a sealed tree a vault keeps for its tenant** (`kvaultd::drives`):
//! the tenancy's own tree, `local` — the pool every vault kept before, the
//! person's first drive there, which every device calls `personal` — and each
//! drive made beside it. What this device records of them is the drive record
//! ([`kotton_peer::daemon::drives`]), one row per vault, tenancy and tree.
//!
//! **Names are sealed, and the vault is where every device reads them.** A
//! made drive's name is sealed under the person's key, bound to the tree, and
//! kept by the vault beside the tree; any device of the person's opens it, the
//! vault never can. So the vault's listing (`TenantDrives`) is how a device
//! learns of a drive another device made, and of one moved away: [`follow`]
//! takes a vault's whole listing as what this device records of the drives
//! made there ([`kotton_peer::daemon::drives::reconcile`]). It runs at every
//! `drive list`, after every verb here that changes a vault, and after every
//! sync pass with a vault (`kotton_sync::engine`), so **every device follows a
//! drive** wherever it was made or moved, at its next pass, without being told.
//!
//! **A move carries the sealed tree under the same key.** This device reads
//! every sealed object of the drive from the vault it lives on and writes it,
//! byte for byte, to a tree made for it at the other — the objects stay sealed
//! under the person's key and neither vault can open them; the device declares
//! the person's own key domain, so a tree in any other domain is refused at the
//! read (`KottonPeerObjectStorage::get_sealed`). Only when the other vault
//! lists every object at its size is the drive retired where it was. The tree
//! at the other vault has an id minted for it there, and its name is sealed
//! afresh for that tree, so the two landlords hold nothing in common for it.
//!
//! **What does not move yet: the first drive.** The tenancy's own tree is what
//! this device's own tree syncs with, at every vault the person keeps drives
//! on (`kotton_sync::engine`); it is kept at each and lives at none alone, so
//! `move` refuses it and says so. A device keeping a made drive's files — and
//! so the first drive becoming one drive among others — is pins' (kotton #55)
//! and the drive paths' (kotton #58).

use crate::users::DeviceUsers as _;
use crate::DeviceRuntime;
use kotton_peer::daemon::drives::{self as record, Drive};
use kotton_peer::KottonPeerObjectStorage;
use kotton_store::runtime::user::UserStore;
use kotton_sys::store::SealedObjectAccess as _;
use kotton_wire::ipc::{DriveDescriptor, MadeDrive, TenantDrive, UserRequest, UserResponse, FIRST_DRIVE_TREE};
use kotton_wire::peer::PairedNode;
use sqlx::SqlitePool;
use std::collections::HashMap;
use std::io;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

/// How long one vault is given to answer one request.
const EACH_VAULT: Duration = Duration::from_secs(20);

/// The longest name a drive may have, in bytes.
pub const MAX_NAME: usize = 128;

fn refused(message: impl Into<String>) -> io::Result<UserResponse> {
    Ok(UserResponse::Error { message: message.into() })
}

/// Bytes each drive holds, by the vault's key and the tree, as the vaults
/// answered this time.
type Sizes = HashMap<([u8; 32], String), u64>;

/// Ask `client`, a vault `user_id` keeps drives on, for every drive it keeps
/// for them, and take its listing as what this device records of the drives
/// made there. Returns the listing.
///
/// A name that does not open under the person's key — a vault that altered
/// it, or one sealed for another tree — names no drive: a drive this device
/// already records keeps the name it has, and one it does not is not recorded,
/// and both are logged.
pub async fn follow(
    store: &UserStore,
    db: &Arc<SqlitePool>,
    user_id: &str,
    vault_key: &[u8; 32],
    client: &KottonPeerObjectStorage,
) -> io::Result<Vec<TenantDrive>> {
    let listed = match ask(client, UserRequest::TenantDrives { user_id: user_id.to_string() }).await? {
        UserResponse::TenantDrivesResult { drives } => drives,
        UserResponse::Error { message } => return Err(io::Error::other(message)),
        other => return Err(io::Error::other(format!("the vault answered {other:?} to TenantDrives"))),
    };
    let recorded = record::all(db, user_id).await?;
    let mut made = Vec::new();
    for drive in listed.iter().filter(|d| d.tree != FIRST_DRIVE_TREE) {
        match store.open_drive_name(&drive.tree, &drive.sealed_name) {
            Ok(name) => made.push((drive.tree.clone(), name)),
            Err(e) => {
                tracing::warn!(user_id, tree = %drive.tree, error = %e, "a drive's name did not open");
                if let Some(kept) = recorded.iter().find(|d| d.vault_key == *vault_key && d.tree == drive.tree) {
                    made.push((drive.tree.clone(), kept.name.clone()));
                }
            }
        }
    }
    record::reconcile(db, user_id, vault_key, &made).await?;
    Ok(listed)
}

async fn ask(client: &KottonPeerObjectStorage, request: UserRequest) -> io::Result<UserResponse> {
    tokio::time::timeout(EACH_VAULT, client.send(&request))
        .await
        .map_err(|_| io::Error::other("the vault did not answer in time"))?
        .map_err(|e| io::Error::other(e.to_string()))
}

async fn dial(runtime: &DeviceRuntime, node: &PairedNode, user_id: &str) -> io::Result<KottonPeerObjectStorage> {
    tokio::time::timeout(EACH_VAULT, runtime.dialer().connect(node.clone(), user_id))
        .await
        .map_err(|_| io::Error::other(format!("the vault '{}' did not answer in time", node.id)))?
        .map_err(|e| io::Error::other(format!("the vault '{}' did not answer: {e}", node.id)))
}

/// Ask every vault `user_id` keeps drives on, following each that answers.
/// What each drive holds, by vault and tree; a vault that does not answer
/// leaves its drives as recorded, and their sizes unknown.
async fn follow_every_vault(runtime: &DeviceRuntime, store: &UserStore, db: &Arc<SqlitePool>, user_id: &str) -> io::Result<Sizes> {
    let mut sizes = Sizes::new();
    for vault in record::list(db, user_id).await? {
        let listed = match dial(runtime, &vault.node, user_id).await {
            Ok(client) => follow(store, db, user_id, &vault.vault_key, &client).await,
            Err(e) => Err(e),
        };
        match listed {
            Ok(listed) => {
                for d in listed {
                    sizes.insert((vault.vault_key, d.tree), d.held);
                }
            }
            Err(e) => tracing::warn!(user_id, vault = %vault.node.id, error = %e, "a vault's drives were not listed"),
        }
    }
    Ok(sizes)
}

fn describe(drive: &Drive, sizes: &Sizes) -> DriveDescriptor {
    DriveDescriptor {
        name: drive.name.clone(),
        vault: drive.node.id.clone(),
        vault_key: hex::encode(drive.vault_key),
        size: sizes.get(&(drive.vault_key, drive.tree.clone())).copied(),
        // What each device keeps is pins' (kotton #55), a record in the drive
        // that nothing writes yet.
        pinned_whole: Vec::new(),
    }
}

/// The vault `named` names among those `user_id` keeps drives on: its label
/// while one carries it, its DID, or its key in hex; or, named by nothing, the
/// one vault there is. `Err` is the sentence the person reads.
async fn vault_named(db: &Arc<SqlitePool>, user_id: &str, named: Option<&str>, flag: &str) -> io::Result<Result<Drive, String>> {
    let vaults = record::list(db, user_id).await?;
    let Some(named) = named else {
        return Ok(match vaults.as_slice() {
            [one] => Ok(one.clone()),
            [] => Err("you keep drives on no vault yet; `vault invite --me` makes one".to_string()),
            many => Err(format!(
                "you keep drives on {} vaults ({}); name one with {flag}",
                many.len(),
                many.iter().map(|v| v.node.id.as_str()).collect::<Vec<_>>().join(", ")
            )),
        });
    };
    let found: Vec<&Drive> = vaults
        .iter()
        .filter(|v| v.node.id == named || v.node.device_did.to_string() == named || hex::encode(v.vault_key) == named)
        .collect();
    Ok(match found.as_slice() {
        [one] => Ok((*one).clone()),
        [] => Err(format!("'{named}' names none of the vaults you keep drives on")),
        many => Err(format!(
            "'{named}' is the label of {} of your vaults ({}); name the one you mean by its DID",
            many.len(),
            many.iter().map(|v| v.node.device_did.to_string()).collect::<Vec<_>>().join(", ")
        )),
    })
}

/// A name a drive may have: some text, short, and not a flag.
fn name_said(name: &str) -> Result<String, String> {
    let name = name.trim();
    if name.is_empty() {
        return Err("a drive needs a name".into());
    }
    if name.len() > MAX_NAME {
        return Err(format!("a drive's name is at most {MAX_NAME} bytes"));
    }
    if name.starts_with('-') || name.chars().any(char::is_control) {
        return Err(format!("'{name}' is not a drive's name: it starts with '-' or holds a control character"));
    }
    Ok(name.to_string())
}

/// `drive create <name> [--on <vault>]`.
pub async fn create(
    runtime: &DeviceRuntime,
    store: &UserStore,
    db: &Arc<SqlitePool>,
    user_id: &str,
    name: &str,
    on: Option<&str>,
) -> io::Result<UserResponse> {
    let name = match name_said(name) {
        Ok(n) => n,
        Err(e) => return refused(format!("drive create: {e}")),
    };
    let vault = match vault_named(db, user_id, on, "--on").await? {
        Ok(v) => v,
        Err(e) => return refused(format!("drive create: {e}")),
    };
    let client = dial(runtime, &vault.node, user_id).await?;
    // What the vaults hold now, so a name another device took is seen here.
    follow(store, db, user_id, &vault.vault_key, &client).await?;
    if let Some(taken) = record::all(db, user_id).await?.into_iter().find(|d| d.name == name) {
        return refused(format!("drive create: you have a drive called '{name}' already, on '{}'", taken.node.id));
    }
    let drive = MadeDrive(rand::random());
    let tree = drive.tree();
    let sealed_name = store.seal_drive_name(&tree, &name).map_err(|e| io::Error::other(format!("{e:#}")))?;
    match ask(&client, UserRequest::TenantDriveMake { user_id: user_id.to_string(), drive, sealed_name }).await? {
        UserResponse::Ok => {}
        UserResponse::Error { message } => return refused(format!("drive create: the vault '{}' refused: {message}", vault.node.id)),
        other => return refused(format!("drive create: the vault answered {other:?}")),
    }
    let listed = follow(store, db, user_id, &vault.vault_key, &client).await?;
    let sizes: Sizes = listed.into_iter().map(|d| ((vault.vault_key, d.tree), d.held)).collect();
    let made = record::all(db, user_id)
        .await?
        .into_iter()
        .find(|d| d.vault_key == vault.vault_key && d.tree == tree)
        .ok_or_else(|| io::Error::other("the vault made the drive but did not list it"))?;
    tracing::info!(user_id, vault = %vault.node.id, "made a drive");
    Ok(UserResponse::Drives { drives: vec![describe(&made, &sizes)] })
}

/// `drive list`: every drive, after asking each vault what it keeps.
pub async fn list(runtime: &DeviceRuntime, store: &UserStore, db: &Arc<SqlitePool>, user_id: &str) -> io::Result<UserResponse> {
    let sizes = follow_every_vault(runtime, store, db, user_id).await?;
    let drives = record::all(db, user_id).await?.iter().map(|d| describe(d, &sizes)).collect();
    Ok(UserResponse::Drives { drives })
}

/// `drive show <name>`: the drives called `name`, one per vault it is kept on.
pub async fn show(runtime: &DeviceRuntime, store: &UserStore, db: &Arc<SqlitePool>, user_id: &str, name: &str) -> io::Result<UserResponse> {
    let sizes = follow_every_vault(runtime, store, db, user_id).await?;
    let drives: Vec<DriveDescriptor> = record::all(db, user_id)
        .await?
        .iter()
        .filter(|d| d.name == name)
        .map(|d| describe(d, &sizes))
        .collect();
    if drives.is_empty() {
        return refused(format!("drive show: you have no drive called '{name}'"));
    }
    Ok(UserResponse::Drives { drives })
}

/// `drive move <name> --to <vault>` (module doc).
pub async fn move_to(
    runtime: &DeviceRuntime,
    store: &UserStore,
    db: &Arc<SqlitePool>,
    user_id: &str,
    name: &str,
    to: &str,
) -> io::Result<UserResponse> {
    let dest = match vault_named(db, user_id, Some(to), "--to").await? {
        Ok(v) => v,
        Err(e) => return refused(format!("drive move: {e}")),
    };
    let named: Vec<Drive> = record::all(db, user_id).await?.into_iter().filter(|d| d.name == name).collect();
    let drive = match named.as_slice() {
        [one] => one.clone(),
        [] => return refused(format!("drive move: you have no drive called '{name}'")),
        many if many.iter().all(Drive::is_first) => {
            return refused(format!(
                "drive move: '{name}' is the tenancy's own tree, kept at each vault you keep drives on ({}); this \
                 device's own tree syncs with it at every one, so it lives at none alone and does not move",
                many.iter().map(|d| d.node.id.as_str()).collect::<Vec<_>>().join(", ")
            ))
        }
        many => {
            return refused(format!(
                "drive move: you have {} drives called '{name}' ({}); there is no one to move",
                many.len(),
                many.iter().map(|d| d.node.id.as_str()).collect::<Vec<_>>().join(", ")
            ))
        }
    };
    let Some(from_id) = MadeDrive::from_tree(&drive.tree) else {
        return refused(format!(
            "drive move: '{name}' is the tenancy's own tree at '{}'; this device's own tree syncs with it at \
             every vault you keep drives on, so it does not move",
            drive.node.id
        ));
    };
    if dest.vault_key == drive.vault_key {
        return refused(format!("drive move: '{name}' lives on '{}' already", dest.node.id));
    }
    let Some(domain) = runtime.user_cek_domain_id(user_id, Some(store)) else {
        return refused("drive move: this device holds no key for you, so it cannot carry a drive");
    };

    let from = dial(runtime, &drive.node, user_id)
        .await?
        .with_remote_mount(drive.tree.clone())
        .with_domain_id(domain.clone());
    let to_id = MadeDrive(rand::random());
    let to_tree = to_id.tree();
    let sealed_name = store.seal_drive_name(&to_tree, name).map_err(|e| io::Error::other(format!("{e:#}")))?;
    let dest_client = dial(runtime, &dest.node, user_id).await?;
    match ask(&dest_client, UserRequest::TenantDriveMake { user_id: user_id.to_string(), drive: to_id, sealed_name }).await? {
        UserResponse::Ok => {}
        UserResponse::Error { message } => return refused(format!("drive move: '{}' refused the drive: {message}", dest.node.id)),
        other => return refused(format!("drive move: '{}' answered {other:?}", dest.node.id)),
    }
    let dest_tree = dest_client.with_remote_mount(to_tree.clone()).with_domain_id(domain);

    // Every object, as sealed, then the listing compared; a carry that fails
    // retires the half-made tree at the other vault and leaves the drive where
    // it was.
    if let Err(e) = carry(&from, &dest_tree).await {
        let _ = ask(&dest_tree, UserRequest::TenantDriveRetire { user_id: user_id.to_string(), drive: to_id }).await;
        return refused(format!("drive move: '{name}' was not moved, and is still on '{}': {e}", drive.node.id));
    }
    let retired = ask(&from, UserRequest::TenantDriveRetire { user_id: user_id.to_string(), drive: from_id }).await;
    let mut sizes = Sizes::new();
    for (vault, client) in [(&drive, &from), (&dest, &dest_tree)] {
        match follow(store, db, user_id, &vault.vault_key, client).await {
            Ok(listed) => sizes.extend(listed.into_iter().map(|d| ((vault.vault_key, d.tree), d.held))),
            Err(e) => tracing::warn!(user_id, vault = %vault.node.id, error = %e, "a vault was not followed after a move"),
        }
    }
    match retired {
        Ok(UserResponse::Ok) => {}
        Ok(UserResponse::Error { message }) => {
            return refused(format!(
                "drive move: '{name}' is on '{}' now, and '{}' still keeps it too: it did not retire it ({message}). \
                 Both are listed until it does",
                dest.node.id, drive.node.id
            ))
        }
        Ok(other) => return refused(format!("drive move: '{}' answered {other:?} to the retire", drive.node.id)),
        Err(e) => {
            return refused(format!(
                "drive move: '{name}' is on '{}' now, and '{}' still keeps it too: {e}",
                dest.node.id, drive.node.id
            ))
        }
    }
    let moved = record::all(db, user_id)
        .await?
        .into_iter()
        .find(|d| d.vault_key == dest.vault_key && d.tree == to_tree)
        .ok_or_else(|| io::Error::other("the drive was moved but the vault it moved to did not list it"))?;
    tracing::info!(user_id, from = %drive.node.id, to = %dest.node.id, "moved a drive");
    Ok(UserResponse::Drives { drives: vec![describe(&moved, &sizes)] })
}

/// Copy every sealed object of `from`'s tree to `to`'s, then hold that `to`
/// lists each at its size.
async fn carry(from: &KottonPeerObjectStorage, to: &KottonPeerObjectStorage) -> Result<(), String> {
    let objects = from.list_sealed(Path::new("")).await.map_err(|e| format!("the drive could not be listed: {e}"))?;
    for object in &objects {
        let key = Path::new(&object.key);
        let blob = from.get_sealed(key).await.map_err(|e| format!("reading {}: {e}", object.key))?;
        to.put_sealed(key, &blob).await.map_err(|e| format!("writing {}: {e}", object.key))?;
    }
    let mut wanted: Vec<(String, u64)> = objects.into_iter().map(|o| (o.key, o.size)).collect();
    let mut landed: Vec<(String, u64)> = to
        .list_sealed(Path::new(""))
        .await
        .map_err(|e| format!("the other vault could not list what it took: {e}"))?
        .into_iter()
        .map(|o| (o.key, o.size))
        .collect();
    wanted.sort();
    landed.sort();
    if wanted != landed {
        return Err(format!("the other vault holds {} objects of {}", landed.len(), wanted.len()));
    }
    Ok(())
}
