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
//! read (`KottonPeerObjectStorage::get_sealed`). The tree at the other vault
//! has an id minted for it there, and its name is sealed afresh for that tree,
//! so the two landlords hold nothing in common for it.
//!
//! **A move is finished in one order, and undone in the reverse.** The tree at
//! the other vault is made under a name sealed *unfinished*
//! (`UserStore::seal_drive_name`), which every device reads as a move in
//! progress and never as a second drive of that name; the objects are
//! copied; the other vault's listing must name every key at its size; only
//! then is the tree named finished (`TenantDriveName`), and only after that is
//! the drive retired where it was ([`carry_and_settle`]). A copy, a check or a
//! naming that fails retires the unfinished tree, asking twice, and the drive
//! stays where it was; the person is told it was not moved. If the other vault
//! will not retire the unfinished tree either, the person is told that too, by
//! the tree's name: `drive list` on every device shows it as unfinished, and
//! the next move of that drive to that vault retires it before it starts.
//!
//! **A listing taken mid-move never makes a device forget the drive.** Until
//! the source is retired, the vault it lives on lists it, so a device that
//! follows there keeps it; the other vault lists it only once it is named
//! finished, which is after it holds every object. Between the naming and the
//! retire both vaults list it, and a device may record it at both for one
//! pass — `drive show` names both and `drive move` refuses the ambiguity —
//! until its next pass at the vault the drive left. A device whose one pass
//! followed the other vault before the naming and the source after the retire
//! has no record of the drive until its next pass; nothing at either vault is
//! lost by it, because the retire comes only after the other vault holds and
//! names every object, and the record is rebuilt from the vaults' listings.
//!
//! **What a move does not hold yet: the drive's lock.** No device writes into
//! a made drive today, so nothing races the copy. Once a device keeps one
//! (pins, kotton #55), a move must hold the drive's mount lock, and refuse
//! while another device's pass holds it; that requirement is recorded on #55,
//! beside the same one for `kvaultd::drives`' retire.
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

/// What a vault said of the person's drives there, as [`follow`] read it.
#[derive(Debug, Default)]
pub struct Followed {
    /// Its whole listing.
    pub listed: Vec<TenantDrive>,
    /// The trees a move made there and did not finish, each with the drive's
    /// name: not drives, and not recorded as drives (module doc).
    pub unfinished: Vec<(String, String)>,
}

/// Ask `client`, a vault `user_id` keeps drives on, for every drive it keeps
/// for them, and take its listing as what this device records of the drives
/// made there.
///
/// A name that does not open under the person's key — a vault that altered
/// it, or one sealed for another tree — names no drive: a drive this device
/// already records keeps the name it has, and one it does not is not recorded,
/// and both are logged. A name sealed unfinished is a move's tree, not a
/// drive, and is returned apart.
pub async fn follow(
    store: &UserStore,
    db: &Arc<SqlitePool>,
    user_id: &str,
    vault_key: &[u8; 32],
    client: &KottonPeerObjectStorage,
) -> io::Result<Followed> {
    let listed = match ask(client, UserRequest::TenantDrives { user_id: user_id.to_string() }).await? {
        UserResponse::TenantDrivesResult { drives } => drives,
        UserResponse::Error { message } => return Err(io::Error::other(message)),
        other => return Err(io::Error::other(format!("the vault answered {other:?} to TenantDrives"))),
    };
    let recorded: Vec<(String, String)> = record::all(db, user_id)
        .await?
        .into_iter()
        .filter(|d| d.vault_key == *vault_key)
        .map(|d| (d.tree, d.name))
        .collect();
    let (made, unfinished) = read_listing(store, user_id, &listed, &recorded);
    record::reconcile(db, user_id, vault_key, &made).await?;
    Ok(Followed { listed, unfinished })
}

/// A tree, and the name the person has for the drive in it.
type Named = (String, String);

/// A vault's listing, read: the made drives it keeps, by tree and name — a
/// name that does not open keeping the name `recorded` has for its tree, or
/// naming no drive — and, apart, the trees a move left unfinished.
fn read_listing(
    store: &UserStore,
    user_id: &str,
    listed: &[TenantDrive],
    recorded: &[(String, String)],
) -> (Vec<Named>, Vec<Named>) {
    let mut made = Vec::new();
    let mut unfinished = Vec::new();
    for drive in listed.iter().filter(|d| d.tree != FIRST_DRIVE_TREE) {
        match store.open_drive_name(&drive.tree, &drive.sealed_name) {
            Ok((name, true)) => made.push((drive.tree.clone(), name)),
            Ok((name, false)) => unfinished.push((drive.tree.clone(), name)),
            Err(e) => {
                tracing::warn!(user_id, tree = %drive.tree, error = %e, "a drive's name did not open");
                if let Some((tree, name)) = recorded.iter().find(|(tree, _)| *tree == drive.tree) {
                    made.push((tree.clone(), name.clone()));
                }
            }
        }
    }
    (made, unfinished)
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
/// What each drive holds, by vault and tree, and every unfinished move's tree
/// as a descriptor; a vault that does not answer leaves its drives as
/// recorded, and their sizes unknown.
async fn follow_every_vault(
    runtime: &DeviceRuntime,
    store: &UserStore,
    db: &Arc<SqlitePool>,
    user_id: &str,
) -> io::Result<(Sizes, Vec<DriveDescriptor>)> {
    let mut sizes = Sizes::new();
    let mut unfinished = Vec::new();
    for vault in record::list(db, user_id).await? {
        let followed = match dial(runtime, &vault.node, user_id).await {
            Ok(client) => follow(store, db, user_id, &vault.vault_key, &client).await,
            Err(e) => Err(e),
        };
        match followed {
            Ok(followed) => {
                for d in followed.listed {
                    sizes.insert((vault.vault_key, d.tree), d.held);
                }
                for (tree, name) in followed.unfinished {
                    unfinished.push(DriveDescriptor {
                        name,
                        vault: vault.node.id.clone(),
                        vault_key: hex::encode(vault.vault_key),
                        size: sizes.get(&(vault.vault_key, tree)).copied(),
                        pinned_whole: Vec::new(),
                        unfinished: true,
                    });
                }
            }
            Err(e) => tracing::warn!(user_id, vault = %vault.node.id, error = %e, "a vault's drives were not listed"),
        }
    }
    Ok((sizes, unfinished))
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
        unfinished: false,
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
    let sealed_name = store.seal_drive_name(&tree, &name, true).map_err(|e| io::Error::other(format!("{e:#}")))?;
    match ask(&client, UserRequest::TenantDriveMake { user_id: user_id.to_string(), drive, sealed_name }).await? {
        UserResponse::Ok => {}
        UserResponse::Error { message } => return refused(format!("drive create: the vault '{}' refused: {message}", vault.node.id)),
        other => return refused(format!("drive create: the vault answered {other:?}")),
    }
    let followed = follow(store, db, user_id, &vault.vault_key, &client).await?;
    let sizes: Sizes = followed.listed.into_iter().map(|d| ((vault.vault_key, d.tree), d.held)).collect();
    let made = record::all(db, user_id)
        .await?
        .into_iter()
        .find(|d| d.vault_key == vault.vault_key && d.tree == tree)
        .ok_or_else(|| io::Error::other("the vault made the drive but did not list it"))?;
    tracing::info!(user_id, vault = %vault.node.id, "made a drive");
    Ok(UserResponse::Drives { drives: vec![describe(&made, &sizes)] })
}

/// `drive list`: every drive, after asking each vault what it keeps, and
/// every unfinished move's tree, marked so.
pub async fn list(runtime: &DeviceRuntime, store: &UserStore, db: &Arc<SqlitePool>, user_id: &str) -> io::Result<UserResponse> {
    let (sizes, unfinished) = follow_every_vault(runtime, store, db, user_id).await?;
    let mut drives: Vec<DriveDescriptor> = record::all(db, user_id).await?.iter().map(|d| describe(d, &sizes)).collect();
    drives.extend(unfinished);
    Ok(UserResponse::Drives { drives })
}

/// `drive show <name>`: the drives called `name`, one per vault it is kept on.
pub async fn show(runtime: &DeviceRuntime, store: &UserStore, db: &Arc<SqlitePool>, user_id: &str, name: &str) -> io::Result<UserResponse> {
    let (sizes, unfinished) = follow_every_vault(runtime, store, db, user_id).await?;
    let mut drives: Vec<DriveDescriptor> = record::all(db, user_id)
        .await?
        .iter()
        .filter(|d| d.name == name)
        .map(|d| describe(d, &sizes))
        .collect();
    drives.extend(unfinished.into_iter().filter(|d| d.name == name));
    if drives.is_empty() {
        return refused(format!("drive show: you have no drive called '{name}'"));
    }
    Ok(UserResponse::Drives { drives })
}

/// One vault a move reads from or writes to: a made drive's tree there, and
/// the vault's tenant verbs. A trait so the order [`carry_and_settle`] keeps
/// can be held against vaults that misbehave.
#[async_trait::async_trait]
pub trait VaultEnd: Send + Sync {
    /// Every sealed object of the tree, by key, with its size.
    async fn objects(&self) -> Result<Vec<(String, u64)>, String>;
    /// One sealed object, as it rests.
    async fn read(&self, key: &str) -> Result<Vec<u8>, String>;
    /// Write one sealed object, as it rests.
    async fn write(&self, key: &str, blob: &[u8]) -> Result<(), String>;
    /// A tenant verb the vault answers `Ok` to, or why not.
    async fn tell(&self, request: UserRequest) -> Result<(), String>;
}

/// A vault reached over the peer link, its sealed verbs pointed at one tree.
struct PeerEnd(KottonPeerObjectStorage);

#[async_trait::async_trait]
impl VaultEnd for PeerEnd {
    async fn objects(&self) -> Result<Vec<(String, u64)>, String> {
        let listed = self.0.list_sealed(Path::new("")).await.map_err(|e| e.to_string())?;
        Ok(listed.into_iter().map(|o| (o.key, o.size)).collect())
    }
    async fn read(&self, key: &str) -> Result<Vec<u8>, String> {
        self.0.get_sealed(Path::new(key)).await.map(|b| b.to_vec()).map_err(|e| e.to_string())
    }
    async fn write(&self, key: &str, blob: &[u8]) -> Result<(), String> {
        self.0.put_sealed(Path::new(key), blob).await.map_err(|e| e.to_string())
    }
    async fn tell(&self, request: UserRequest) -> Result<(), String> {
        match ask(&self.0, request).await.map_err(|e| e.to_string())? {
            UserResponse::Ok => Ok(()),
            UserResponse::Error { message } => Err(message),
            other => Err(format!("the vault answered {other:?}")),
        }
    }
}

/// How a move came out ([`carry_and_settle`]).
#[derive(Debug, PartialEq, Eq)]
pub enum Carried {
    /// The other vault holds the drive, named; the vault it left retired it.
    Moved,
    /// The other vault holds the drive, named, and the vault it left did not
    /// retire it: both keep it, and both list it.
    SourceKept(String),
    /// The drive is where it was; the unfinished tree at the other vault was
    /// retired. Why it was not moved.
    NotMoved(String),
    /// The drive is where it was, and the other vault would not retire the
    /// unfinished tree either: why it was not moved, and why that tree stays.
    NotMovedTreeLeft { why: String, left: String },
}

/// Copy the drive, check it, name it finished at `to`, then retire it at
/// `from` — and, if any step before the naming fails, retire the unfinished
/// tree at `to`, asking twice (module doc). `to` was made under a name sealed
/// unfinished; `finished_name` is the drive's name sealed finished for `to_id`.
pub async fn carry_and_settle(
    user_id: &str,
    from: &dyn VaultEnd,
    from_id: MadeDrive,
    to: &dyn VaultEnd,
    to_id: MadeDrive,
    finished_name: Vec<u8>,
) -> Carried {
    let carried = async {
        let mut wanted = from.objects().await.map_err(|e| format!("the drive could not be listed: {e}"))?;
        for (key, _) in &wanted {
            let blob = from.read(key).await.map_err(|e| format!("reading {key}: {e}"))?;
            to.write(key, &blob).await.map_err(|e| format!("writing {key}: {e}"))?;
        }
        let mut landed = to.objects().await.map_err(|e| format!("the other vault could not list what it took: {e}"))?;
        wanted.sort();
        landed.sort();
        if wanted != landed {
            let missing = wanted.iter().filter(|w| !landed.contains(w)).count();
            return Err(format!(
                "the other vault does not list {missing} of the {} objects at the size they were sent",
                wanted.len()
            ));
        }
        to.tell(UserRequest::TenantDriveName { user_id: user_id.to_string(), drive: to_id, sealed_name: finished_name })
            .await
            .map_err(|e| format!("the other vault did not name the drive: {e}"))
    }
    .await;
    if let Err(why) = carried {
        let retire = || to.tell(UserRequest::TenantDriveRetire { user_id: user_id.to_string(), drive: to_id });
        return match retire().await {
            Ok(()) => Carried::NotMoved(why),
            Err(_) => match retire().await {
                Ok(()) => Carried::NotMoved(why),
                Err(left) => Carried::NotMovedTreeLeft { why, left },
            },
        };
    }
    match from.tell(UserRequest::TenantDriveRetire { user_id: user_id.to_string(), drive: from_id }).await {
        Ok(()) => Carried::Moved,
        Err(e) => Carried::SourceKept(e),
    }
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

    let from = dial(runtime, &drive.node, user_id).await?;
    let dest_client = dial(runtime, &dest.node, user_id).await?;
    // An earlier move of this drive to this vault that left its tree there.
    for (tree, left) in follow(store, db, user_id, &dest.vault_key, &dest_client).await?.unfinished {
        if left != name {
            continue;
        }
        if let Some(stale) = MadeDrive::from_tree(&tree) {
            let retired = ask(&dest_client, UserRequest::TenantDriveRetire { user_id: user_id.to_string(), drive: stale }).await;
            if !matches!(retired, Ok(UserResponse::Ok)) {
                return refused(format!(
                    "drive move: '{}' still keeps an unfinished copy of '{name}' under {tree}, from an earlier move, \
                     and did not retire it now; '{name}' is still on '{}'",
                    dest.node.id, drive.node.id
                ));
            }
        }
    }
    let to_id = MadeDrive(rand::random());
    let to_tree = to_id.tree();
    let unfinished_name = store.seal_drive_name(&to_tree, name, false).map_err(|e| io::Error::other(format!("{e:#}")))?;
    let finished_name = store.seal_drive_name(&to_tree, name, true).map_err(|e| io::Error::other(format!("{e:#}")))?;
    match ask(&dest_client, UserRequest::TenantDriveMake { user_id: user_id.to_string(), drive: to_id, sealed_name: unfinished_name }).await? {
        UserResponse::Ok => {}
        UserResponse::Error { message } => return refused(format!("drive move: '{}' refused the drive: {message}", dest.node.id)),
        other => return refused(format!("drive move: '{}' answered {other:?}", dest.node.id)),
    }
    let from = PeerEnd(from.with_remote_mount(drive.tree.clone()).with_domain_id(domain.clone()));
    let to_end = PeerEnd(dest_client.with_remote_mount(to_tree.clone()).with_domain_id(domain));
    let carried = carry_and_settle(user_id, &from, from_id, &to_end, to_id, finished_name).await;

    let mut sizes = Sizes::new();
    for (vault, end) in [(&drive, &from), (&dest, &to_end)] {
        match follow(store, db, user_id, &vault.vault_key, &end.0).await {
            Ok(followed) => sizes.extend(followed.listed.into_iter().map(|d| ((vault.vault_key, d.tree), d.held))),
            Err(e) => tracing::warn!(user_id, vault = %vault.node.id, error = %e, "a vault was not followed after a move"),
        }
    }
    let (src, dst) = (drive.node.id.as_str(), dest.node.id.as_str());
    match carried {
        Carried::Moved => {}
        Carried::NotMoved(why) => return refused(format!("drive move: '{name}' was not moved, and is still on '{src}': {why}")),
        Carried::NotMovedTreeLeft { why, left } => {
            return refused(format!(
                "drive move: '{name}' was not moved, and is still on '{src}': {why}. '{dst}' also keeps an unfinished \
                 copy of it under {to_tree}, which it did not retire ({left}): `drive list` shows it as unfinished, \
                 and moving '{name}' to '{dst}' again retires it first"
            ))
        }
        Carried::SourceKept(e) => {
            return refused(format!(
                "drive move: '{name}' is on '{dst}' now, and '{src}' still keeps it too: it did not retire it ({e}). \
                 Both are listed until it does"
            ))
        }
    }
    let moved = record::all(db, user_id)
        .await?
        .into_iter()
        .find(|d| d.vault_key == dest.vault_key && d.tree == to_tree)
        .ok_or_else(|| io::Error::other("the drive was moved but the vault it moved to did not list it"))?;
    tracing::info!(user_id, from = %src, to = %dst, "moved a drive");
    Ok(UserResponse::Drives { drives: vec![describe(&moved, &sizes)] })
}

#[cfg(test)]
mod tests {
    //! The order a move keeps, held against vaults that misbehave. These are
    //! fakes at the [`VaultEnd`] seam, not vaults: the suite's fixture
    //! (`drive_sync::a_vault_keeps_several_drives_and_a_moved_drive_is_followed_by_every_device`)
    //! has real vaults that answer, and cannot make one list a wrong size,
    //! drop a write or refuse a retire.
    use super::*;
    use std::sync::Mutex;

    /// A vault's tree, in memory, with what can go wrong at it.
    #[derive(Default)]
    struct Fake {
        objects: Mutex<Vec<(String, Vec<u8>)>>,
        /// Every tenant verb it was told, by name.
        told: Mutex<Vec<&'static str>>,
        /// The write of this key fails.
        fail_write: Option<&'static str>,
        /// Its listing says this key is one byte larger than it is.
        misreport: Option<&'static str>,
        /// Its listing leaves this key out, as a vault that lost the write.
        hides: Option<&'static str>,
        /// It answers every retire with an error.
        refuse_retire: bool,
    }

    impl Fake {
        fn holding(objects: &[(&str, &[u8])]) -> Self {
            Self {
                objects: Mutex::new(objects.iter().map(|(k, v)| (k.to_string(), v.to_vec())).collect()),
                ..Self::default()
            }
        }
        fn keys(&self) -> Vec<String> {
            self.objects.lock().unwrap().iter().map(|(k, _)| k.clone()).collect()
        }
        fn told(&self) -> Vec<&'static str> {
            self.told.lock().unwrap().clone()
        }
    }

    #[async_trait::async_trait]
    impl VaultEnd for Fake {
        async fn objects(&self) -> Result<Vec<(String, u64)>, String> {
            Ok(self
                .objects
                .lock()
                .unwrap()
                .iter()
                .filter(|(k, _)| self.hides != Some(k.as_str()))
                .map(|(k, v)| (k.clone(), v.len() as u64 + u64::from(self.misreport == Some(k.as_str()))))
                .collect())
        }
        async fn read(&self, key: &str) -> Result<Vec<u8>, String> {
            self.objects.lock().unwrap().iter().find(|(k, _)| k == key).map(|(_, v)| v.clone()).ok_or("not found".into())
        }
        async fn write(&self, key: &str, blob: &[u8]) -> Result<(), String> {
            if self.fail_write == Some(key) {
                return Err("the connection dropped".into());
            }
            self.objects.lock().unwrap().push((key.to_string(), blob.to_vec()));
            Ok(())
        }
        async fn tell(&self, request: UserRequest) -> Result<(), String> {
            let verb = request.variant_name();
            self.told.lock().unwrap().push(verb);
            match request {
                UserRequest::TenantDriveRetire { .. } if self.refuse_retire => Err("the vault would not".into()),
                UserRequest::TenantDriveRetire { .. } => {
                    self.objects.lock().unwrap().clear();
                    Ok(())
                }
                _ => Ok(()),
            }
        }
    }

    const FROM: MadeDrive = MadeDrive([1; 16]);
    const TO: MadeDrive = MadeDrive([2; 16]);

    fn source() -> Fake {
        Fake::holding(&[("p/one", b"one"), ("p/two", b"two two")])
    }

    async fn settle(from: &Fake, to: &Fake) -> Carried {
        carry_and_settle("alice", from, FROM, to, TO, b"finished".to_vec()).await
    }

    /// The order when every vault answers: copy, name the other vault's tree
    /// finished, and only then retire the drive where it was.
    #[tokio::test]
    async fn a_move_names_the_copy_finished_before_it_retires_the_source() {
        let (from, to) = (source(), Fake::default());
        assert_eq!(settle(&from, &to).await, Carried::Moved);
        assert_eq!(to.keys(), ["p/one", "p/two"]);
        assert_eq!(to.told(), ["TenantDriveName"]);
        assert_eq!(from.told(), ["TenantDriveRetire"]);
    }

    /// **A destination that lists a key at the wrong size, or not at all,
    /// leaves the drive where it was**: the source is told nothing and keeps
    /// every object, the unfinished tree is retired and never named, and the
    /// person reads that it was not moved and why.
    #[tokio::test]
    async fn a_destination_that_lists_a_wrong_size_or_misses_a_key_leaves_the_drive_where_it_was() {
        for (to, said) in [
            (Fake { misreport: Some("p/two"), ..Fake::default() }, "does not list 1 of the 2 objects at the size they were sent"),
            (Fake { hides: Some("p/two"), ..Fake::default() }, "does not list 1 of the 2 objects"),
        ] {
            let from = source();
            match settle(&from, &to).await {
                Carried::NotMoved(why) => assert!(why.contains(said), "{why}"),
                other => panic!("a destination that does not list what it took was taken: {other:?}"),
            }
            assert_eq!(to.told(), ["TenantDriveRetire"], "the unfinished tree was not retired, or was named");
            assert!(to.keys().is_empty(), "the unfinished tree kept what it took");
            assert!(from.told().is_empty(), "the source was told something: {:?}", from.told());
            assert_eq!(from.keys(), ["p/one", "p/two"], "the source lost an object");
        }
    }

    /// **A copy that fails mid-way leaves the drive where it was**, and the
    /// unfinished tree retired.
    #[tokio::test]
    async fn a_copy_that_fails_mid_way_leaves_the_drive_where_it_was() {
        let (from, to) = (source(), Fake { fail_write: Some("p/two"), ..Fake::default() });
        match settle(&from, &to).await {
            Carried::NotMoved(why) => assert!(why.contains("writing p/two") && why.contains("dropped"), "{why}"),
            other => panic!("{other:?}"),
        }
        assert_eq!(to.told(), ["TenantDriveRetire"]);
        assert!(to.keys().is_empty(), "the unfinished tree kept what it took");
        assert!(from.told().is_empty());
        assert_eq!(from.keys(), ["p/one", "p/two"]);
    }

    /// **A destination that will not retire the unfinished tree is asked
    /// twice, and then named to the person**: the drive is where it was, and
    /// the answer carries both why it was not moved and why the tree stays —
    /// which `move_to` says by the tree's name. The tree was never named
    /// finished, so no device reads it as a second drive.
    #[tokio::test]
    async fn an_unfinished_tree_the_destination_will_not_retire_is_said_and_never_named_finished() {
        let (from, to) = (source(), Fake { fail_write: Some("p/two"), refuse_retire: true, ..Fake::default() });
        match settle(&from, &to).await {
            Carried::NotMovedTreeLeft { why, left } => {
                assert!(why.contains("writing p/two"), "{why}");
                assert!(left.contains("would not"), "{left}");
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(to.told(), ["TenantDriveRetire", "TenantDriveRetire"], "the retire was not asked twice, or the tree was named");
        assert_eq!(from.keys(), ["p/one", "p/two"]);
        assert!(from.told().is_empty());
    }

    /// A source that will not retire the drive after the copy is named
    /// finished: the move happened, both vaults keep it, and the person is
    /// told so rather than that it moved.
    #[tokio::test]
    async fn a_source_that_will_not_retire_leaves_the_drive_at_both() {
        let (from, to) = (Fake { refuse_retire: true, ..source() }, Fake::default());
        match settle(&from, &to).await {
            Carried::SourceKept(e) => assert!(e.contains("would not"), "{e}"),
            other => panic!("{other:?}"),
        }
        assert_eq!(to.told(), ["TenantDriveName"]);
        assert_eq!(from.keys(), ["p/one", "p/two"]);
    }

    /// **A move's unfinished tree is never read as a drive.** In a listing, a
    /// name sealed finished is a drive; one sealed unfinished is set apart,
    /// so no device records a second drive of that name; one that does not
    /// open keeps the name this device has for its tree, or names nothing.
    #[test]
    fn a_listing_sets_an_unfinished_move_apart_from_the_drives() {
        let dir = tempfile::tempdir().unwrap();
        let store = UserStore::create(
            "alice",
            "did:key:zAlice",
            dir.path().to_path_buf(),
            kotton_store::runtime::UserKeys::new(Some([7; 32])),
            &kotton_store::LocalShelves(kotton_fs::OsFilesystem),
        )
        .unwrap();
        let tree = |id: u8| MadeDrive([id; 16]).tree();
        let listed = vec![
            TenantDrive { tree: FIRST_DRIVE_TREE.into(), sealed_name: vec![], held: 1 },
            TenantDrive { tree: tree(1), sealed_name: store.seal_drive_name(&tree(1), "photos", true).unwrap(), held: 1 },
            TenantDrive { tree: tree(2), sealed_name: store.seal_drive_name(&tree(2), "photos", false).unwrap(), held: 1 },
            TenantDrive { tree: tree(3), sealed_name: b"altered".to_vec(), held: 1 },
            TenantDrive { tree: tree(4), sealed_name: b"altered".to_vec(), held: 1 },
        ];
        let recorded = vec![(tree(3), "work".to_string())];
        let (made, unfinished) = read_listing(&store, "alice", &listed, &recorded);
        assert_eq!(made, [(tree(1), "photos".to_string()), (tree(3), "work".to_string())]);
        assert_eq!(unfinished, [(tree(2), "photos".to_string())]);
    }
}
