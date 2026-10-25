// SPDX-License-Identifier: AGPL-3.0-or-later
//! **What each device keeps of the person's drives** (kotton #55): the pin
//! settings, read and written as records, resolved to what a pass keeps, and
//! read back as the two notices.
//!
//! The protocol's storage model, on what a person's devices keep: every device of the
//! person's sees every drive; each device has one default for the drives it
//! has not been told about, and a drive or a folder is set the other way on
//! that device; the nearest setting wins, a folder's over its drive's over the
//! device's default, and `default` at any level means follow the one above.
//! The first device's default is whole and a device paired later defaults to
//! on demand. The device that creates a drive keeps it whole until told
//! otherwise. When no device keeps a drive whole the person is told; when a
//! device that keeps a drive whole runs short of room it says so and names the
//! setting that keeps less. One verb collects: `pin <drive> whole`.
//!
//! **A setting is a record in the person's drive.** One `sh.kotton.pin` record
//! per device and scope (`kotton_schemas`'s core set; kotton-protocol #20's
//! record: device, scope, value; on the wire `kotton_wire::ipc::PinSetting`).
//! Records ride the history log as sealed segments in the index packs a device
//! always keeps (`kotton_store::packed::CONTENT_PACK_PREFIX`), so every device
//! of the person's reads every device's settings and the drive reads none. The
//! device is named by the DID of the key it presents — inside the person's own
//! sealed records, where the only reader is the person; nothing here is sent
//! to a vault, so nothing in it is a key a vault can join on. A device writes
//! only its own settings (`pin` is "what this device holds"), so two devices
//! never write one record, and a record's last write is its device's word.
//!
//! **What is enforced, today: the first drive.** A device keeps a tree of the
//! person's first drive and of no made drive yet (drive paths, kotton #58; the
//! first drive becoming one drive among others, #124), so pins are enforced on
//! the first drive and on nothing else. A setting for a made drive is refused,
//! and no device is counted as keeping a made drive whole ([`whole_on`]), so
//! `status` says of every made drive that only its vault holds it — which is
//! true until #58 and #124 give a device something to keep. The creating
//! device's whole pin is written then, not before.
//!
//! **Where the records live, today.** The records ride the person's record log,
//! which a device's tree carries to the first drive on each vault — the one
//! drive a device keeps a tree of. So a setting about a made drive is a record
//! in the person's first drive, not in the made drive's own tree: a made drive
//! has no tree on a device until drive paths (kotton #58) and the first drive
//! becoming one drive among others (#124) give it one. This is the "per-person
//! record home" kotton #55's first comment names. It is the decision taken
//! here, pending its edit to the protocol's storage model; the protocol says
//! "a record in the drive", and the two meet when #124 lands.
//!
//! **Resolution is a rule, not a check.** [`resolve`] answers, for a device and
//! a place in a drive, the nearest setting and its value; nothing else decides
//! what a device keeps, and nothing refuses a setting for being "too far". A
//! folder's setting covers the folders beneath it, and the deepest wins. A
//! device with no default record says nothing about other devices' holdings:
//! another device's silence is never read as "whole", so the no-whole notice
//! errs toward telling. This device's own silence is its behaviour before pins,
//! which kept everything — whole — and the first pass after it writes that
//! down ([`state_default`]).
//!
//! **What is kept is the person's tree.** A pin is over the paths the person
//! names (`files/` in the store). The daemon's own objects — the membership
//! set, read marks, a model's weights — are kept whole on every device whatever
//! the pins say, because a device needs them to run offline; they are named by
//! no setting, so they are never the setting a short-of-room notice names.

use kotton_record::{registry::SchemaRegistry, record_cmds::Record, SqliteRecordStore};
use kotton_schemas::membership::{Posture, Role};
use kotton_store::runtime::user::sync::{Keep, KeepReport};
use kotton_store::runtime::user::UserStore;
use kotton_wire::ipc::{
    DeviceStatus, DriveHeld, PinNotice, PinReadout, PinScope, PinSetting, PinValue, FIRST_DRIVE_NAME,
};
use serde_json::{json, Value};
use sqlx::SqlitePool;
use std::collections::BTreeSet;
use std::io;
use std::sync::{Arc, RwLock};

/// The NSID a setting is written under.
const PIN_NSID: &str = kotton_common::namespace::NSID_PIN;

/// The store key the person's tree is rooted at: a pin is over these paths.
const PERSON_TREE: &str = kotton_store::runtime::user::files::PERSON_TREE_ROOT;

/// What this device keeps when it has stated nothing: what every device kept
/// before pins, and the first device's default.
pub const UNSTATED: PinValue = PinValue::Whole;

/// What a device that joins the person keeps by default (the protocol's
/// storage model: a device paired later defaults to on demand).
pub const JOINED: PinValue = PinValue::OnDemand;

/// What this device is called where it names itself among the person's devices.
pub const THIS_DEVICE: &str = "this device";

fn err(e: impl std::fmt::Display) -> io::Error {
    io::Error::other(e.to_string())
}

/// The record id of `device`'s setting at `scope`: one per device and scope,
/// so setting a scope again replaces the record. A digest, so the id is as
/// opaque as the rest of the sealed record and the same on every device.
fn record_id(device: &str, scope: &PinScope) -> String {
    let said = serde_json::to_string(&(device, scope)).unwrap_or_default();
    format!("pin-{}", &blake3::hash(said.as_bytes()).to_hex()[..32])
}

fn to_record(setting: &PinSetting) -> Value {
    let (scope, drive, folder) = match &setting.scope {
        PinScope::Default => ("default", None, None),
        PinScope::Drive { drive } => ("drive", Some(drive.clone()), None),
        PinScope::Folder { drive, folder } => ("folder", Some(drive.clone()), Some(folder.clone())),
    };
    json!({
        "id": record_id(&setting.device, &setting.scope),
        "device": setting.device,
        "scope": scope,
        "drive": drive,
        "folder": folder,
        "value": setting.value.said(),
    })
}

fn from_record(body: &Value) -> Option<PinSetting> {
    let text = |f: &str| body.get(f).and_then(Value::as_str).map(str::to_string);
    let scope = match text("scope")?.as_str() {
        "default" => PinScope::Default,
        "drive" => PinScope::Drive { drive: text("drive")? },
        "folder" => PinScope::Folder { drive: text("drive")?, folder: text("folder")? },
        _ => return None,
    };
    Some(PinSetting { device: text("device")?, scope, value: PinValue::parse(&text("value")?)? })
}

/// Every pin setting of every device of the person's this device has read.
pub async fn settings(registry: &RwLock<SchemaRegistry>, store: &SqliteRecordStore) -> io::Result<Vec<PinSetting>> {
    let rows = Record::new(registry, store).query(PIN_NSID, Vec::new(), None, None, None).await.map_err(err)?;
    Ok(rows.iter().filter_map(from_record).collect())
}

/// Held by every write of a device's default and across [`state_default`]'s
/// read and write, so stating the default when none is stated cannot write
/// over a default stated meanwhile — a `pin default`, or a joining device's
/// `on-demand`. A device's records are written by its one daemon, so a lock
/// in that process covers every writer of them; the record store's handles do
/// not share a transaction.
static DEFAULT_WRITE: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Write `device`'s setting at `scope` as `value`; `None` is `default` — the
/// drive or folder follows the setting above it, which is its record removed.
/// The device's own default has nothing above it, and is refused `None`.
pub async fn write(
    registry: &RwLock<SchemaRegistry>,
    store: &SqliteRecordStore,
    device: &str,
    scope: &PinScope,
    value: Option<PinValue>,
) -> io::Result<()> {
    let _default = match scope {
        PinScope::Default => Some(DEFAULT_WRITE.lock().await),
        _ => None,
    };
    write_held(registry, store, device, scope, value).await
}

/// [`write`], with [`DEFAULT_WRITE`] already held where it must be.
async fn write_held(
    registry: &RwLock<SchemaRegistry>,
    store: &SqliteRecordStore,
    device: &str,
    scope: &PinScope,
    value: Option<PinValue>,
) -> io::Result<()> {
    let records = Record::new(registry, store);
    match value {
        Some(value) => {
            let setting = PinSetting { device: device.to_string(), scope: scope.clone(), value };
            records.insert(PIN_NSID, to_record(&setting)).await.map_err(err)?;
        }
        None if *scope == PinScope::Default => {
            return Err(err("a device's default has nothing above it to follow: say `whole` or `on-demand`"))
        }
        None => {
            let id = record_id(device, scope);
            let held = records
                .query(PIN_NSID, vec![("id".into(), json!(id))], Some(1), None, None)
                .await
                .map_err(err)?;
            if !held.is_empty() {
                records.delete(PIN_NSID, &id).await.map_err(err)?;
            }
        }
    }
    Ok(())
}

/// This device's default, as its records say it, or `None` when it has
/// stated none.
fn stated_default(all: &[PinSetting], device: &str) -> Option<PinValue> {
    all.iter().find(|s| s.device == device && s.scope == PinScope::Default).map(|s| s.value)
}

/// Write this device's default down, as [`UNSTATED`], when it has stated
/// none: what it does is then what every other device reads of it. Called
/// before every pass, so a device that predates pins, or recovered the
/// identity, says what it keeps at its first pass. Returns whether it wrote.
pub async fn state_default(registry: &RwLock<SchemaRegistry>, store: &SqliteRecordStore, device: &str) -> io::Result<bool> {
    let _held = DEFAULT_WRITE.lock().await;
    if stated_default(&settings(registry, store).await?, device).is_some() {
        return Ok(false);
    }
    write_held(registry, store, device, &PinScope::Default, Some(UNSTATED)).await?;
    Ok(true)
}

/// **The nearest setting wins** (module doc): for `device`, at `folder` (a
/// path in `drive` from its root, or `None` for the drive as a whole), the
/// value it keeps and the setting that decided it — the deepest folder setting
/// at or above `folder`, else the drive's, else the device's default, else
/// `unstated`, which decides as the default would.
pub fn resolve(all: &[PinSetting], device: &str, drive: &str, folder: Option<&str>, unstated: PinValue) -> (PinValue, PinScope) {
    let mine = || all.iter().filter(|s| s.device == device);
    if let Some(path) = folder {
        let nearest = mine()
            .filter_map(|s| match &s.scope {
                PinScope::Folder { drive: d, folder: f } if d == drive && covers(f, path) => Some((f.len(), s)),
                _ => None,
            })
            .max_by_key(|(depth, _)| *depth);
        if let Some((_, s)) = nearest {
            return (s.value, s.scope.clone());
        }
    }
    if let Some(s) = mine().find(|s| matches!(&s.scope, PinScope::Drive { drive: d } if d == drive)) {
        return (s.value, s.scope.clone());
    }
    (stated_default(all, device).unwrap_or(unstated), PinScope::Default)
}

/// Whether the folder `folder` is `path` or holds it.
fn covers(folder: &str, path: &str) -> bool {
    path == folder || path.strip_prefix(folder).is_some_and(|rest| rest.starts_with('/'))
}

/// Whether `device` keeps `drive` whole: the drive as a whole resolves whole,
/// and no folder of it is set on demand.
pub fn keeps_whole(all: &[PinSetting], device: &str, drive: &str, unstated: PinValue) -> bool {
    resolve(all, device, drive, None, unstated).0 == PinValue::Whole
        && !all.iter().any(|s| {
            s.device == device
                && s.value == PinValue::OnDemand
                && matches!(&s.scope, PinScope::Folder { drive: d, .. } if d == drive)
        })
}

/// What a pass keeps of the person's first drive on `device` (the one drive a
/// device keeps a tree of), within `budget`: each path the store names, read
/// as the person's path, resolved; the daemon's own objects kept whole by no
/// setting (module doc).
pub fn keep(all: Vec<PinSetting>, device: &str, budget: Option<u64>) -> Keep {
    let device = device.to_string();
    Keep {
        whole: Box::new(move |key: &str| {
            let Some(rest) = key.strip_prefix(PERSON_TREE).and_then(|r| r.strip_prefix('/')) else {
                return Some(String::new());
            };
            let path = format!("/{rest}");
            let (value, scope) = resolve(&all, &device, FIRST_DRIVE_NAME, Some(&path), UNSTATED);
            (value == PinValue::Whole).then(|| match scope {
                PinScope::Default => "default".to_string(),
                other => other.said(),
            })
        }),
        budget,
    }
}

/// The person's devices whose settings this device reads, by DID and name:
/// itself, and every own device of theirs that holds the data keys
/// (`Posture::Full`) in the membership set. A device revoked is no member, so
/// its settings are no longer read — which is how a removed device stops
/// keeping anything whole.
pub async fn devices(store: &UserStore, me: &str) -> Vec<(String, String)> {
    use kotton_peer::membership::Membership as _;
    let mut out = vec![(me.to_string(), THIS_DEVICE.to_string())];
    match store.list_members().await {
        Ok(members) => {
            for m in members {
                let full = matches!(m.posture, None | Some(Posture::Full));
                if matches!(m.role, Role::OwnDevice) && full && m.did != me {
                    let name = m.label.clone().unwrap_or_else(|| m.did.clone());
                    out.push((m.did, name));
                }
            }
        }
        Err(e) => tracing::warn!(error = format!("{e:#}"), "pins: the membership set did not read; only this device's settings are counted"),
    }
    out
}

/// The names of the devices among `devices` that keep `drive` whole.
///
/// None for a made drive: no device keeps a tree of one yet (module doc), so
/// none keeps it whole, whatever its settings say.
pub fn whole_on(all: &[PinSetting], devices: &[(String, String)], me: &str, drive: &str) -> Vec<String> {
    if drive != FIRST_DRIVE_NAME {
        return Vec::new();
    }
    devices
        .iter()
        .filter(|(did, _)| {
            // Another device's silence is not "whole" (module doc).
            let unstated = if did == me { UNSTATED } else { PinValue::OnDemand };
            keeps_whole(all, did, drive, unstated)
        })
        .map(|(_, name)| name.clone())
        .collect()
}

/// The person's drives, by name, once each, in the order recorded.
pub async fn drive_names(db: &Arc<SqlitePool>, user_id: &str) -> io::Result<Vec<String>> {
    let mut names: Vec<String> = Vec::new();
    for d in kotton_peer::daemon::drives::all(db, user_id).await? {
        if !names.contains(&d.name) {
            names.push(d.name);
        }
    }
    Ok(names)
}

/// Every notice: each drive no device keeps whole, and each drive this
/// device's last pass found short of room.
pub async fn notices(db: &Arc<SqlitePool>, user_id: &str, all: &[PinSetting], devices: &[(String, String)], me: &str) -> io::Result<Vec<PinNotice>> {
    let mut out = Vec::new();
    for drive in drive_names(db, user_id).await? {
        if whole_on(all, devices, me, &drive).is_empty() {
            out.push(PinNotice::NoWholeDevice { drive });
        }
    }
    let rows: Vec<(String, i64, Option<i64>, i64, String)> = sqlx::query_as(
        "SELECT drive, held, budget, wanted, settings FROM pin_room WHERE user_id = ? ORDER BY drive",
    )
    .bind(user_id)
    .fetch_all(db.as_ref())
    .await
    .map_err(err)?;
    for (drive, held, budget, wanted, settings) in rows {
        out.push(PinNotice::ShortOfRoom {
            drive,
            settings: serde_json::from_str(&settings).unwrap_or_default(),
            held: held as u64,
            budget: budget.map(|b| b as u64),
            wanted: wanted as u64,
        });
    }
    Ok(out)
}

/// Keep what a pass of `drive` found of the room: a row while it is short, and
/// none once it fits. The settings named are the person's; the daemon's own
/// objects are named by none (module doc).
pub async fn note_room(db: &SqlitePool, user_id: &str, drive: &str, report: &KeepReport) -> io::Result<()> {
    let settings: Vec<&String> = report.short.iter().filter(|s| !s.is_empty()).collect();
    if report.short.is_empty() {
        sqlx::query("DELETE FROM pin_room WHERE user_id = ? AND drive = ?")
            .bind(user_id)
            .bind(drive)
            .execute(db)
            .await
            .map_err(err)?;
        return Ok(());
    }
    sqlx::query(
        "INSERT INTO pin_room (user_id, drive, held, budget, wanted, settings, observed_at) VALUES (?, ?, ?, ?, ?, ?, ?) \
         ON CONFLICT (user_id, drive) DO UPDATE SET held = excluded.held, budget = excluded.budget, \
         wanted = excluded.wanted, settings = excluded.settings, observed_at = excluded.observed_at",
    )
    .bind(user_id)
    .bind(drive)
    .bind(report.held as i64)
    .bind(report.budget.map(|b| b as i64))
    .bind(report.wanted as i64)
    .bind(serde_json::to_string(&settings).map_err(err)?)
    .bind(kotton_common::time::now_secs())
    .execute(db)
    .await
    .map_err(err)?;
    Ok(())
}

/// The room this device gives the drive reached through the node `node_id`:
/// the cache budget the person's mount for that node records (`mount_configs`
/// in their own database, as `peer mount add <node> … --budget <bytes>` sets
/// it), or `None` for no bound but the disk's. The mount's `pins` column is
/// the mesh's and is not read: what a device keeps is its pin settings.
pub async fn budget(db: &SqlitePool, user_id: &str, node_id: &str) -> io::Result<Option<u64>> {
    let b: Option<i64> = sqlx::query_scalar(
        "SELECT cache_budget_bytes FROM mount_configs WHERE user_id = ? AND node_id = ? \
         AND cache_budget_bytes IS NOT NULL ORDER BY mounted_at DESC LIMIT 1",
    )
    .bind(user_id)
    .bind(node_id)
    .fetch_optional(db)
    .await
    .map_err(err)?;
    Ok(b.map(|b| b as u64))
}

/// Everything a reader of this device's pins needs, read once.
pub struct Read {
    pub all: Vec<PinSetting>,
    pub devices: Vec<(String, String)>,
    pub me: String,
}

impl Read {
    pub async fn now(registry: &RwLock<SchemaRegistry>, records: &SqliteRecordStore, store: &UserStore, me: &str) -> io::Result<Self> {
        Ok(Self { all: settings(registry, records).await?, devices: devices(store, me).await, me: me.to_string() })
    }

    /// The names of the devices that keep `drive` whole.
    pub fn whole_on(&self, drive: &str) -> Vec<String> {
        whole_on(&self.all, &self.devices, &self.me, drive)
    }

    /// `pin list`: this device's default and exceptions, and the notices.
    pub async fn readout(&self, db: &Arc<SqlitePool>, user_id: &str) -> io::Result<PinReadout> {
        let mut exceptions: Vec<PinSetting> =
            self.all.iter().filter(|s| s.device == self.me && s.scope != PinScope::Default).cloned().collect();
        exceptions.sort_by_key(|s| s.scope.said());
        Ok(PinReadout {
            default: stated_default(&self.all, &self.me).unwrap_or(UNSTATED),
            exceptions,
            notices: notices(db, user_id, &self.all, &self.devices, &self.me).await?,
        })
    }

    /// `status`: what this device keeps of each drive, and the notices.
    pub async fn status(&self, db: &Arc<SqlitePool>, user_id: &str, last_sync_at: Option<i64>) -> io::Result<DeviceStatus> {
        let readout = self.readout(db, user_id).await?;
        let recorded = kotton_peer::daemon::drives::all(db, user_id).await?;
        let mut drives = Vec::new();
        for name in drive_names(db, user_id).await? {
            let vaults: BTreeSet<String> =
                recorded.iter().filter(|d| d.name == name).map(|d| d.node.id.clone()).collect();
            let folders = readout
                .exceptions
                .iter()
                .filter(|s| matches!(&s.scope, PinScope::Folder { drive, .. } if *drive == name))
                .cloned()
                .collect();
            drives.push(DriveHeld {
                keeps: (name == FIRST_DRIVE_NAME).then(|| resolve(&self.all, &self.me, &name, None, UNSTATED).0),
                pinned_whole: self.whole_on(&name),
                vaults: vaults.into_iter().collect(),
                folders,
                name,
            });
        }
        Ok(DeviceStatus { last_sync_at, default: readout.default, drives, notices: readout.notices })
    }
}

/// `pin <scope> <value>`, on this device `me`: refused for a drive the person
/// does not have, else written as this device's record (module doc), and
/// answered with what this device keeps after.
#[allow(clippy::too_many_arguments)]
pub async fn set(
    registry: &RwLock<SchemaRegistry>,
    records: &SqliteRecordStore,
    store: &UserStore,
    db: &Arc<SqlitePool>,
    user_id: &str,
    me: &str,
    scope: &PinScope,
    value: Option<PinValue>,
) -> io::Result<Result<PinReadout, String>> {
    if let PinScope::Drive { drive } | PinScope::Folder { drive, .. } = scope {
        let names = drive_names(db, user_id).await?;
        if !names.contains(drive) {
            return Ok(Err(format!(
                "you have no drive called '{drive}'{}; `drive list` names them",
                if names.is_empty() { String::new() } else { format!(" (you have {})", names.join(", ")) }
            )));
        }
        if drive != FIRST_DRIVE_NAME {
            return Ok(Err(format!(
                "'{drive}' is a drive this device keeps no tree of yet, so there is nothing of it to keep \
                 whole or on demand here; its vault holds all of it. Pins hold for '{FIRST_DRIVE_NAME}' until \
                 a device can keep a made drive (kotton #58)"
            )));
        }
    }
    if let Err(e) = write(registry, records, me, scope, value).await {
        return Ok(Err(e.to_string()));
    }
    Ok(Ok(Read::now(registry, records, store, me).await?.readout(db, user_id).await?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(device: &str, scope: PinScope, value: PinValue) -> PinSetting {
        PinSetting { device: device.into(), scope, value }
    }
    fn folder(f: &str) -> PinScope {
        PinScope::Folder { drive: "personal".into(), folder: f.into() }
    }

    /// **The nearest setting wins**: a folder's over its drive's over the
    /// device's default, the deepest folder first, a folder covering what is
    /// beneath it and not a sibling that shares its prefix; and another
    /// device's settings decide nothing here.
    #[test]
    fn the_nearest_setting_wins() {
        let all = vec![
            at("b", PinScope::Default, PinValue::OnDemand),
            at("b", folder("/photos"), PinValue::Whole),
            at("b", folder("/photos/raw"), PinValue::OnDemand),
            at("a", PinScope::Default, PinValue::Whole),
            at("a", PinScope::Drive { drive: "work".into() }, PinValue::OnDemand),
        ];
        let v = |device: &str, drive: &str, path: &str| resolve(&all, device, drive, Some(path), UNSTATED).0;
        assert_eq!(v("b", "personal", "/notes/a.md"), PinValue::OnDemand, "the default");
        assert_eq!(v("b", "personal", "/photos/a.jpg"), PinValue::Whole, "the folder over the default");
        assert_eq!(v("b", "personal", "/photos"), PinValue::Whole, "the folder itself");
        assert_eq!(v("b", "personal", "/photos/raw/a.dng"), PinValue::OnDemand, "the deeper folder");
        assert_eq!(v("b", "personal", "/photosynthesis.md"), PinValue::OnDemand, "a sibling sharing a prefix");
        assert_eq!(v("a", "personal", "/photos/a.jpg"), PinValue::Whole, "b's folder is b's");
        assert_eq!(v("a", "work", "/x"), PinValue::OnDemand, "the drive over the default");
        assert_eq!(resolve(&all, "c", "personal", None, PinValue::OnDemand).0, PinValue::OnDemand, "silence is `unstated`");
        assert_eq!(resolve(&all, "b", "personal", Some("/photos/a"), UNSTATED).1, folder("/photos"), "it names the setting");

        assert!(keeps_whole(&all, "a", "personal", UNSTATED));
        assert!(!keeps_whole(&all, "a", "work", UNSTATED));
        assert!(!keeps_whole(&all, "b", "personal", UNSTATED), "b's default is on demand");
        let mut whole_b = all.clone();
        whole_b.push(at("b", PinScope::Drive { drive: "personal".into() }, PinValue::Whole));
        assert!(!keeps_whole(&whole_b, "b", "personal", UNSTATED), "a folder on demand is not the drive whole");
    }

    /// **A pass keeps what the pins say, and names the setting that keeps
    /// it**: a path in the person's tree resolves; the daemon's own objects
    /// are kept by no setting.
    #[test]
    fn a_pass_keeps_what_resolves_whole_and_names_the_setting() {
        let all = vec![at("b", PinScope::Default, PinValue::OnDemand), at("b", folder("/photos"), PinValue::Whole)];
        let keep = keep(all, "b", Some(9));
        assert_eq!((keep.whole)("files/photos/a.jpg").as_deref(), Some("personal:/photos"));
        assert_eq!((keep.whole)("files/notes/a.md"), None);
        assert_eq!((keep.whole)("network/members/did"), Some(String::new()), "a daemon object is kept, by no setting");
        assert_eq!(keep.budget, Some(9));
        let unstated = super::keep(vec![], "a", None);
        assert_eq!((unstated.whole)("files/notes/a.md").as_deref(), Some("default"), "silence keeps everything");
    }

    /// **Another device's silence is not "whole"**, and this device's is.
    #[test]
    fn whole_on_counts_only_what_a_device_said() {
        let devices = vec![("a".to_string(), THIS_DEVICE.to_string()), ("b".to_string(), "laptop".to_string()), ("c".to_string(), "phone".to_string())];
        let all = vec![at("b", PinScope::Default, PinValue::Whole)];
        assert_eq!(whole_on(&all, &devices, "a", "personal"), [THIS_DEVICE, "laptop"]);
        let all = vec![at("a", PinScope::Default, PinValue::OnDemand)];
        assert!(whole_on(&all, &devices, "a", "personal").is_empty());
    }

    /// **A made drive is kept whole by no device yet**, whatever the settings
    /// say: no device keeps a tree of one (module doc).
    #[test]
    fn no_device_keeps_a_made_drive_whole_yet() {
        let devices = vec![("a".to_string(), THIS_DEVICE.to_string())];
        let all = vec![at("a", PinScope::Default, PinValue::Whole), at("a", PinScope::Drive { drive: "photos".into() }, PinValue::Whole)];
        assert!(whole_on(&all, &devices, "a", "photos").is_empty());
        assert_eq!(whole_on(&all, &devices, "a", FIRST_DRIVE_NAME), [THIS_DEVICE]);
    }

    /// **Stating the default never writes over one stated meanwhile.** A
    /// device's first pass states `whole` if it has stated nothing, while a
    /// `pin default on-demand` — or a joining device's — lands at the same
    /// time: whichever runs first, the device ends `on-demand`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn stating_the_default_does_not_write_over_one_stated_meanwhile() {
        use crate::users::DeviceUsers as _;
        let temp = tempfile::TempDir::new().unwrap();
        let secrets = std::sync::Arc::new(kotton_secret::MemorySecrets::new());
        let rt = crate::DeviceRuntime::new_with_secrets(temp.path().to_path_buf(), crate::config::RuntimeConfig::default(), secrets)
            .await
            .unwrap();
        rt.create_user("alice", "canyon-orbit-velvet-fish-hospital").await.unwrap();
        let records = std::sync::Arc::new(kotton_record::open::user_record_store(rt.base_dir(), "alice", rt.secrets()).unwrap());
        let registry = std::sync::Arc::clone(&rt.schema_registry);
        for round in 0..20 {
            let me = format!("did:key:z6Mkround{round}");
            let stating = tokio::spawn({
                let (registry, records, me) = (std::sync::Arc::clone(&registry), std::sync::Arc::clone(&records), me.clone());
                async move { state_default(&registry, &records, &me).await.unwrap() }
            });
            let saying = tokio::spawn({
                let (registry, records, me) = (std::sync::Arc::clone(&registry), std::sync::Arc::clone(&records), me.clone());
                async move { write(&registry, &records, &me, &PinScope::Default, Some(PinValue::OnDemand)).await.unwrap() }
            });
            stating.await.unwrap();
            saying.await.unwrap();
            let all = settings(&registry, &records).await.unwrap();
            assert_eq!(stated_default(&all, &me), Some(PinValue::OnDemand), "round {round}: the stated default was written over");
        }
    }

    /// The record is the setting, field for field, and its id is the device
    /// and the scope, so a scope set again is one record.
    #[test]
    fn a_setting_is_one_record_per_device_and_scope() {
        let s = at("did:key:z6Mk", folder("/photos"), PinValue::Whole);
        assert_eq!(from_record(&to_record(&s)).unwrap(), s);
        let again = at("did:key:z6Mk", folder("/photos"), PinValue::OnDemand);
        assert_eq!(to_record(&s)["id"], to_record(&again)["id"]);
        assert_ne!(to_record(&s)["id"], to_record(&at("did:key:other", folder("/photos"), PinValue::Whole))["id"]);
        let schema = kotton_schemas::core::CoreSchema::Pin.definition();
        let body = to_record(&s);
        for field in schema.fields {
            assert!(body.get(&field.name).is_some(), "the record has no {}", field.name);
        }
    }
}
