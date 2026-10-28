// SPDX-License-Identifier: AGPL-3.0-or-later
//! **What each device keeps of the person's drives** (kotton #55, #171): the
//! pin settings, kept on the device that set them and resolved to what a pass
//! keeps; the whole-keeper claims a device publishes in a drive; and the two
//! notices, read from them.
//!
//! The protocol's storage model (kotton-protocol #26), on
//! what a person's devices keep: every device of the person's sees every
//! drive; each device has one default for the drives it has not been told
//! about, and a drive or a folder is set the other way on that device; the
//! nearest setting wins, a folder's over its drive's over the device's
//! default, and `default` at any level means follow the one above. The first
//! device's default is whole and a device paired later defaults to on demand.
//! The device that creates a drive keeps it whole until told otherwise. When
//! no device keeps a drive whole the person is told; when a device that keeps
//! a drive whole runs short of room it says so and names the setting that
//! keeps less. One verb collects: `pin <drive> whole`.
//!
//! **A setting is the device's own, and stays on it.** The default and every
//! exception live in this device's own database (`pin_settings`, migration
//! `0030`), one row per person and scope ([`settings`], [`write`]); nothing of
//! them replicates, and no setting is written to any drive. That is the
//! per-device "keep on this device / fetch when opened" switch people know
//! from other services, and a device wiped and paired again comes back to on
//! demand ([`JOINED`]). On the wire a setting is `kotton_wire::ipc::PinSetting`,
//! sent only to this device's own client, and it names no device.
//!
//! **What a device publishes: one claim per drive it keeps whole.** A
//! whole-keeper claim ([`Claim`]) is a sealed record in that drive
//! (`sh.kotton.keeps-whole`, `kotton_schemas`'s core set) holding the device,
//! by the DID of the key it presents, and the drive's id
//! (`kotton_peer::daemon::drives::Drive::id`), and nothing else; that it
//! exists is the claim. Its record id is a digest of the two, so a device
//! claims a drive once. **It is written by that device alone** ([`claim`]):
//! each device reconciles its own claims to its own settings — at every `pin`
//! and before every pass, so the first device's first pass writes its claim —
//! and never touches another device's. **A claim is withdrawn by a delete**,
//! when its device stops keeping the drive whole (`pin … on-demand`), and the
//! delete replicates as one: every write of a record is a new version
//! (kotton #158), so a device flipping whole, on demand and whole again in one
//! second still says each. The cost is bounded: one small record per keeping
//! device per drive, written only when the claim changes, never a walk.
//!
//! **The telling reads the claims, and nothing else** ([`Read`], [`whole_on`],
//! [`notices`]): `drive list`'s and `status`'s *which devices keep it whole*,
//! and the notice that none does, read the claims for each drive this device
//! records, by its id. A claim counts for nothing once its device is no longer
//! in the person's device set ([`devices`], the membership set's own filter):
//! a removed device cannot write, and nobody else may delete its claims, so
//! readers set them aside instead. A device lost but not removed is counted
//! until the person removes it. A drive retired by a move leaves no claim:
//! its claims are in it and go with it, and a drive this device no longer
//! records is told of to nobody. Claims ride the history log in the index
//! packs every device always keeps, so the drive reads none of them.
//!
//! **The index comes first.** A pass pulls every index pack — and with it
//! every claim — before anything consults a setting: the first step of a pass
//! skips content packs only, without reading what the settings say of them,
//! and the settings decide only which content packs the second step fetches
//! (`kotton_store::runtime::user::sync::UserStore::sync_mount_keeping`). So
//! nothing a setting or a claim says can withhold the index.
//!
//! **Where claims live, today: the first drive.** A device keeps a tree of the
//! person's first drive and of no made drive yet (drive paths, kotton #58; the
//! first drive becoming one drive among others, #124), so a device keeps, and
//! claims, only the first drive, under `kotton_wire::ipc::FIRST_DRIVE_ID`; its
//! claims ride the person's record log in that drive. A setting for a made
//! drive is refused, and no claim names one, so `status` says of every made
//! drive that only its vault holds it — which is true. **Seam, not built:** the
//! creating device's claim at `drive create` is written once a device keeps a
//! tree of a made drive (#58, #124); and a person's claims in a drive are to be
//! sealed under that person's key and under no key a drive's holders would
//! share, which today's record log is (one person per log) and a shared drive
//! must keep.
//!
//! **What kotton #155 wrote is migrated in place** ([`migrate`]): it kept
//! every setting as an `sh.kotton.pin` record in the person's drive. The first
//! time this device reads its settings it moves each of its own such records
//! into its own database — never over a setting stated here since — and
//! deletes it from the drive, and the delete replicates. Another device's are
//! that device's to move; nothing reads them meanwhile.
//!
//! **Resolution is a rule, not a check.** [`resolve`] answers, for a place in
//! a drive, the nearest setting and its value; nothing else decides what a
//! device keeps, and nothing refuses a setting for being "too far". A folder's
//! setting covers the folders beneath it, and the deepest wins. This device's
//! silence is its behaviour before pins, which kept everything — whole.
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
    DeviceStatus, DriveHeld, PinNotice, PinReadout, PinScope, PinSetting, PinValue, FIRST_DRIVE_ID, FIRST_DRIVE_NAME,
};
use serde_json::{json, Value};
use sqlx::SqlitePool;
use std::collections::BTreeSet;
use std::io;
use std::sync::{Arc, RwLock};

/// The NSID kotton #155 wrote settings under, read only to migrate them.
const PIN_NSID: &str = kotton_common::namespace::NSID_PIN;

/// The NSID a whole-keeper claim is written under.
const CLAIM_NSID: &str = kotton_common::namespace::NSID_KEEPS_WHOLE;

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

/// A scope as the `pin_settings` row keys it: the scope's kind, the drive and
/// the folder, empty where the kind has none.
fn scope_row(scope: &PinScope) -> (&'static str, &str, &str) {
    match scope {
        PinScope::Default => ("default", "", ""),
        PinScope::Drive { drive } => ("drive", drive, ""),
        PinScope::Folder { drive, folder } => ("folder", drive, folder),
    }
}

fn scope_of(kind: &str, drive: String, folder: String) -> Option<PinScope> {
    Some(match kind {
        "default" => PinScope::Default,
        "drive" => PinScope::Drive { drive },
        "folder" => PinScope::Folder { drive, folder },
        _ => return None,
    })
}

/// Every pin setting this device holds for `user_id`, from its own database.
pub async fn settings(db: &SqlitePool, user_id: &str) -> io::Result<Vec<PinSetting>> {
    let rows: Vec<(String, String, String, String)> = sqlx::query_as(
        "SELECT scope, drive, folder, value FROM pin_settings WHERE user_id = ? ORDER BY scope, drive, folder",
    )
    .bind(user_id)
    .fetch_all(db)
    .await
    .map_err(err)?;
    Ok(rows
        .into_iter()
        .filter_map(|(kind, drive, folder, value)| Some(PinSetting { scope: scope_of(&kind, drive, folder)?, value: PinValue::parse(&value)? }))
        .collect())
}

/// Write this device's setting at `scope` as `value`, in its own database;
/// `None` is `default` — the drive or folder follows the setting above it,
/// which is its row removed. The device's default has nothing above it, and is
/// refused `None`. Nothing is written to any drive.
pub async fn write(db: &SqlitePool, user_id: &str, scope: &PinScope, value: Option<PinValue>) -> io::Result<()> {
    let (kind, drive, folder) = scope_row(scope);
    match value {
        Some(value) => {
            sqlx::query(
                "INSERT INTO pin_settings (user_id, scope, drive, folder, value, set_at) VALUES (?, ?, ?, ?, ?, ?) \
                 ON CONFLICT (user_id, scope, drive, folder) DO UPDATE SET value = excluded.value, set_at = excluded.set_at",
            )
            .bind(user_id)
            .bind(kind)
            .bind(drive)
            .bind(folder)
            .bind(value.said())
            .bind(kotton_common::time::now_secs())
            .execute(db)
            .await
            .map_err(err)?;
        }
        None if *scope == PinScope::Default => {
            return Err(err("a device's default has nothing above it to follow: say `whole` or `on-demand`"))
        }
        None => {
            sqlx::query("DELETE FROM pin_settings WHERE user_id = ? AND scope = ? AND drive = ? AND folder = ?")
                .bind(user_id)
                .bind(kind)
                .bind(drive)
                .bind(folder)
                .execute(db)
                .await
                .map_err(err)?;
        }
    }
    Ok(())
}

/// A setting as kotton #155 wrote it, an `sh.kotton.pin` record: the device
/// it was about, and the setting.
fn from_pin_record(body: &Value) -> Option<(String, PinSetting)> {
    let text = |f: &str| body.get(f).and_then(Value::as_str).map(str::to_string);
    let scope = scope_of(&text("scope")?, text("drive").unwrap_or_default(), text("folder").unwrap_or_default())?;
    Some((text("device")?, PinSetting { scope, value: PinValue::parse(&text("value")?)? }))
}

/// **Move this device's settings out of the drive** (module doc): each
/// `sh.kotton.pin` record kotton #155 wrote about `me` is kept in this
/// device's own database, unless a setting at that scope is stated here
/// already, and deleted from the drive; the delete replicates. Another
/// device's records are left for that device to move. Returns how many it
/// moved. Idempotent: once moved, there are none of this device's to move.
pub async fn migrate(
    registry: &RwLock<SchemaRegistry>,
    records: &SqliteRecordStore,
    db: &SqlitePool,
    user_id: &str,
    me: &str,
) -> io::Result<usize> {
    let rows = Record::new(registry, records).query(PIN_NSID, Vec::new(), None, None, None).await.map_err(err)?;
    let mut moved = 0;
    for body in rows {
        let (Some((device, setting)), Some(id)) = (from_pin_record(&body), body.get("_id").and_then(Value::as_str)) else {
            continue;
        };
        if device != me {
            continue;
        }
        let (kind, drive, folder) = scope_row(&setting.scope);
        sqlx::query(
            "INSERT INTO pin_settings (user_id, scope, drive, folder, value, set_at) VALUES (?, ?, ?, ?, ?, ?) \
             ON CONFLICT (user_id, scope, drive, folder) DO NOTHING",
        )
        .bind(user_id)
        .bind(kind)
        .bind(drive)
        .bind(folder)
        .bind(setting.value.said())
        .bind(kotton_common::time::now_secs())
        .execute(db)
        .await
        .map_err(err)?;
        withdraw(registry, records, PIN_NSID, id).await.map_err(|e| {
            tracing::warn!(user_id, error = format!("{e:#}"), "pins: a setting kept in the drive was not deleted from it");
            err("a pin setting this device kept in the drive was moved here, and was not deleted from the drive; it is tried again at the next pass")
        })?;
        moved += 1;
    }
    Ok(moved)
}

/// Delete the record `id` under `nsid`, **a delete already made counted as
/// made**: a withdrawal is idempotent, so two callers withdrawing one record
/// at once — a `pin` while a pass runs, or the first `status` after an
/// upgrade during the first pass — both succeed, and the tombstone is the
/// state both wanted. No lock is needed for it: this device is the only
/// writer of its own claims and its own #155 settings, so a record found
/// already deleted was deleted by this device, for the same reason.
async fn withdraw(registry: &RwLock<SchemaRegistry>, records: &SqliteRecordStore, nsid: &str, id: &str) -> anyhow::Result<()> {
    match Record::new(registry, records).delete(nsid, id).await {
        Err(e) if matches!(e.downcast_ref(), Some(kotton_record::record_store::RecordStoreError::RecordNotFound(_))) => Ok(()),
        done => done,
    }
}

/// This device's default, as its settings say it, or `None` when it has
/// stated none.
fn stated_default(all: &[PinSetting]) -> Option<PinValue> {
    all.iter().find(|s| s.scope == PinScope::Default).map(|s| s.value)
}

/// **The nearest setting wins** (module doc): at `folder` (a path in `drive`
/// from its root, or `None` for the drive as a whole), the value this device
/// keeps and the setting that decided it — the deepest folder setting at or
/// above `folder`, else the drive's, else the device's default, else
/// [`UNSTATED`].
pub fn resolve(all: &[PinSetting], drive: &str, folder: Option<&str>) -> (PinValue, PinScope) {
    if let Some(path) = folder {
        let nearest = all
            .iter()
            .filter_map(|s| match &s.scope {
                PinScope::Folder { drive: d, folder: f } if d == drive && covers(f, path) => Some((f.len(), s)),
                _ => None,
            })
            .max_by_key(|(depth, _)| *depth);
        if let Some((_, s)) = nearest {
            return (s.value, s.scope.clone());
        }
    }
    if let Some(s) = all.iter().find(|s| matches!(&s.scope, PinScope::Drive { drive: d } if d == drive)) {
        return (s.value, s.scope.clone());
    }
    (stated_default(all).unwrap_or(UNSTATED), PinScope::Default)
}

/// Whether the folder `folder` is `path` or holds it.
fn covers(folder: &str, path: &str) -> bool {
    path == folder || path.strip_prefix(folder).is_some_and(|rest| rest.starts_with('/'))
}

/// Whether this device's settings keep `drive` whole: the drive as a whole
/// resolves whole, and no folder of it is set on demand.
pub fn keeps_whole(all: &[PinSetting], drive: &str) -> bool {
    resolve(all, drive, None).0 == PinValue::Whole
        && !all
            .iter()
            .any(|s| s.value == PinValue::OnDemand && matches!(&s.scope, PinScope::Folder { drive: d, .. } if d == drive))
}

/// What a pass keeps of the person's first drive on this device (the one
/// drive a device keeps a tree of), within `budget`: each path the store
/// names, read as the person's path, resolved; the daemon's own objects kept
/// whole by no setting (module doc).
pub fn keep(all: Vec<PinSetting>, budget: Option<u64>) -> Keep {
    Keep {
        whole: Box::new(move |key: &str| {
            let Some(rest) = key.strip_prefix(PERSON_TREE).and_then(|r| r.strip_prefix('/')) else {
                return Some(String::new());
            };
            let path = format!("/{rest}");
            let (value, scope) = resolve(&all, FIRST_DRIVE_NAME, Some(&path));
            (value == PinValue::Whole).then(|| match scope {
                PinScope::Default => "default".to_string(),
                other => other.said(),
            })
        }),
        budget,
    }
}

/// A whole-keeper claim (module doc): `device` keeps the drive whose id is
/// `drive` whole.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Claim {
    /// The DID of the key the device presents.
    pub device: String,
    /// The drive's id (`kotton_peer::daemon::drives::Drive::id`).
    pub drive: String,
}

impl Claim {
    /// The record id: one per device and drive, a digest so it is as opaque
    /// as the rest of the sealed record and the same on every device.
    fn record_id(&self) -> String {
        let said = serde_json::to_string(&(&self.device, &self.drive)).unwrap_or_default();
        format!("keeps-whole-{}", &blake3::hash(said.as_bytes()).to_hex()[..32])
    }

    fn to_record(&self) -> Value {
        json!({ "id": self.record_id(), "device": self.device, "drive": self.drive })
    }

    fn from_record(body: &Value) -> Option<Self> {
        let text = |f: &str| body.get(f).and_then(Value::as_str).map(str::to_string);
        Some(Self { device: text("device")?, drive: text("drive")? })
    }
}

/// Every whole-keeper claim this device has read: its own, and every other
/// device's its passes have brought from the drive.
pub async fn claims(registry: &RwLock<SchemaRegistry>, records: &SqliteRecordStore) -> io::Result<Vec<Claim>> {
    let rows = Record::new(registry, records).query(CLAIM_NSID, Vec::new(), None, None, None).await.map_err(err)?;
    Ok(rows.iter().filter_map(Claim::from_record).collect())
}

/// The drives this device keeps a tree of, by id: the first drive, and no
/// made drive yet (module doc).
const KEPT_TREES: &[(&str, &str)] = &[(FIRST_DRIVE_ID, FIRST_DRIVE_NAME)];

/// **This device's claims, made to say what its settings keep** (module doc):
/// a claim for each drive it keeps a tree of and keeps whole, and none for
/// any other. Only `me`'s claims are read or written; a claim already there
/// is not written again, and one no longer true is deleted. Returns whether
/// it changed any.
pub async fn claim(registry: &RwLock<SchemaRegistry>, records: &SqliteRecordStore, all: &[PinSetting], me: &str) -> io::Result<bool> {
    let wanted: Vec<Claim> = KEPT_TREES
        .iter()
        .filter(|(_, name)| keeps_whole(all, name))
        .map(|(id, _)| Claim { device: me.to_string(), drive: id.to_string() })
        .collect();
    let mine: Vec<Claim> = claims(registry, records)
        .await
        .map_err(|e| {
            tracing::warn!(error = %e, "pins: this device's claims did not read");
            err("this device's claims to keep a drive whole did not read, so none was made or withdrawn")
        })?
        .into_iter()
        .filter(|c| c.device == me)
        .collect();
    let mut changed = false;
    for gone in mine.iter().filter(|c| !wanted.contains(c)) {
        withdraw(registry, records, CLAIM_NSID, &gone.record_id()).await.map_err(|e| {
            tracing::warn!(error = format!("{e:#}"), "pins: a claim was not withdrawn");
            err("this device's claim to keep a drive whole was not withdrawn; it is tried again at the next pass")
        })?;
        changed = true;
    }
    for new in wanted.iter().filter(|c| !mine.contains(c)) {
        Record::new(registry, records).insert(CLAIM_NSID, new.to_record()).await.map_err(|e| {
            tracing::warn!(error = format!("{e:#}"), "pins: a claim was not written");
            err("this device's claim to keep a drive whole was not written; it is tried again at the next pass")
        })?;
        changed = true;
    }
    Ok(changed)
}

/// The person's devices whose claims count, by DID and name: this device, and
/// every own device of theirs that holds the data keys (`Posture::Full`) in
/// the membership set. A device removed is no member, so its claims count for
/// nothing — which is how a removed device stops keeping anything whole.
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
        Err(e) => tracing::warn!(error = format!("{e:#}"), "pins: the membership set did not read; only this device's claims are counted"),
    }
    out
}

/// The names of the devices among `devices` that claim the drive whose id is
/// `drive` whole: the claims, and nothing else (module doc). `None` — a drive
/// recorded before ids, until its vault is next listed — is claimed by nobody.
pub fn whole_on(claims: &[Claim], devices: &[(String, String)], drive: Option<&str>) -> Vec<String> {
    let Some(drive) = drive else { return Vec::new() };
    devices
        .iter()
        .filter(|(did, _)| claims.iter().any(|c| c.device == *did && c.drive == drive))
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

/// Every notice: each drive this device records that no device claims whole,
/// and each drive this device's last pass found short of room. A drive kept at
/// several vaults is one drive, by its id, and told of once.
pub async fn notices(db: &Arc<SqlitePool>, user_id: &str, claims: &[Claim], devices: &[(String, String)]) -> io::Result<Vec<PinNotice>> {
    let mut out = Vec::new();
    let mut told: Vec<(String, Option<String>)> = Vec::new();
    for d in kotton_peer::daemon::drives::all(db, user_id).await? {
        let key = (d.name.clone(), d.id.clone());
        if told.contains(&key) {
            continue;
        }
        told.push(key);
        let notice = PinNotice::NoWholeDevice { drive: d.name.clone() };
        if whole_on(claims, devices, d.id.as_deref()).is_empty() && !out.contains(&notice) {
            out.push(notice);
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

/// Everything a reader of this device's pins needs, read once: this device's
/// settings, every claim it has read, and the devices whose claims count.
pub struct Read {
    pub settings: Vec<PinSetting>,
    pub claims: Vec<Claim>,
    pub devices: Vec<(String, String)>,
}

impl Read {
    /// Read them, moving any of this device's settings kotton #155 left in the
    /// drive into its own database first ([`migrate`]).
    pub async fn now(
        registry: &RwLock<SchemaRegistry>,
        records: &SqliteRecordStore,
        store: &UserStore,
        db: &SqlitePool,
        user_id: &str,
        me: &str,
    ) -> io::Result<Self> {
        migrate(registry, records, db, user_id, me).await?;
        Ok(Self { settings: settings(db, user_id).await?, claims: claims(registry, records).await?, devices: devices(store, me).await })
    }

    /// The names of the devices that claim the drive whose id is `drive` whole.
    pub fn whole_on(&self, drive: Option<&str>) -> Vec<String> {
        whole_on(&self.claims, &self.devices, drive)
    }

    /// `pin list`: this device's default and exceptions, and the notices.
    pub async fn readout(&self, db: &Arc<SqlitePool>, user_id: &str) -> io::Result<PinReadout> {
        let mut exceptions: Vec<PinSetting> = self.settings.iter().filter(|s| s.scope != PinScope::Default).cloned().collect();
        exceptions.sort_by_key(|s| s.scope.said());
        Ok(PinReadout {
            default: stated_default(&self.settings).unwrap_or(UNSTATED),
            exceptions,
            notices: notices(db, user_id, &self.claims, &self.devices).await?,
        })
    }

    /// `status`: what this device keeps of each drive, the devices that claim
    /// each whole, and the notices.
    pub async fn status(&self, db: &Arc<SqlitePool>, user_id: &str, last_sync_at: Option<i64>) -> io::Result<DeviceStatus> {
        let readout = self.readout(db, user_id).await?;
        let recorded = kotton_peer::daemon::drives::all(db, user_id).await?;
        let mut drives = Vec::new();
        for name in drive_names(db, user_id).await? {
            let copies: Vec<_> = recorded.iter().filter(|d| d.name == name).collect();
            let vaults: BTreeSet<String> = copies.iter().map(|d| d.node.id.clone()).collect();
            let mut pinned_whole: Vec<String> = Vec::new();
            for d in &copies {
                for device in self.whole_on(d.id.as_deref()) {
                    if !pinned_whole.contains(&device) {
                        pinned_whole.push(device);
                    }
                }
            }
            let folders = readout
                .exceptions
                .iter()
                .filter(|s| matches!(&s.scope, PinScope::Folder { drive, .. } if *drive == name))
                .cloned()
                .collect();
            drives.push(DriveHeld {
                keeps: (name == FIRST_DRIVE_NAME).then(|| resolve(&self.settings, &name, None).0),
                pinned_whole,
                vaults: vaults.into_iter().collect(),
                folders,
                name,
            });
        }
        Ok(DeviceStatus { last_sync_at, default: readout.default, drives, notices: readout.notices })
    }
}

/// `pin <scope> <value>`, on this device `me`: refused for a drive the person
/// does not have, else written to this device's own database, this device's
/// claims made to say what it now keeps ([`claim`]), and answered with what
/// this device keeps after.
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
    // Held here, where the setting is kept, whatever client sent the scope: a
    // folder no setting could keep is refused, not kept.
    let scope = &match scope.clone().normalised() {
        Ok(scope) => scope,
        Err(e) => return Ok(Err(e)),
    };
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
    migrate(registry, records, db, user_id, me).await?;
    if let Err(e) = write(db, user_id, scope, value).await {
        return Ok(Err(e.to_string()));
    }
    claim(registry, records, &settings(db, user_id).await?, me).await?;
    Ok(Ok(Read::now(registry, records, store, db, user_id, me).await?.readout(db, user_id).await?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(scope: PinScope, value: PinValue) -> PinSetting {
        PinSetting { scope, value }
    }
    fn folder(f: &str) -> PinScope {
        PinScope::Folder { drive: "personal".into(), folder: f.into() }
    }

    /// **The nearest setting wins**: a folder's over its drive's over the
    /// device's default, the deepest folder first, a folder covering what is
    /// beneath it and not a sibling that shares its prefix.
    #[test]
    fn the_nearest_setting_wins() {
        let all = vec![
            at(PinScope::Default, PinValue::OnDemand),
            at(folder("/photos"), PinValue::Whole),
            at(folder("/photos/raw"), PinValue::OnDemand),
            at(PinScope::Drive { drive: "work".into() }, PinValue::Whole),
        ];
        let v = |drive: &str, path: &str| resolve(&all, drive, Some(path)).0;
        assert_eq!(v("personal", "/notes/a.md"), PinValue::OnDemand, "the default");
        assert_eq!(v("personal", "/photos/a.jpg"), PinValue::Whole, "the folder over the default");
        assert_eq!(v("personal", "/photos"), PinValue::Whole, "the folder itself");
        assert_eq!(v("personal", "/photos/raw/a.dng"), PinValue::OnDemand, "the deeper folder");
        assert_eq!(v("personal", "/photosynthesis.md"), PinValue::OnDemand, "a sibling sharing a prefix");
        assert_eq!(v("work", "/x"), PinValue::Whole, "the drive over the default");
        assert_eq!(resolve(&[], "personal", None).0, UNSTATED, "silence is the behaviour before pins");
        assert_eq!(resolve(&all, "personal", Some("/photos/a")).1, folder("/photos"), "it names the setting");

        assert!(keeps_whole(&all, "work"));
        assert!(!keeps_whole(&all, "personal"), "the default is on demand");
        let mut whole = all.clone();
        whole.push(at(PinScope::Drive { drive: "personal".into() }, PinValue::Whole));
        assert!(!keeps_whole(&whole, "personal"), "a folder on demand is not the drive whole");
        assert!(keeps_whole(&[], FIRST_DRIVE_NAME), "silence keeps everything");
    }

    /// **A pass keeps what the pins say, and names the setting that keeps
    /// it**: a path in the person's tree resolves; the daemon's own objects
    /// are kept by no setting.
    #[test]
    fn a_pass_keeps_what_resolves_whole_and_names_the_setting() {
        let all = vec![at(PinScope::Default, PinValue::OnDemand), at(folder("/photos"), PinValue::Whole)];
        let keep = keep(all, Some(9));
        assert_eq!((keep.whole)("files/photos/a.jpg").as_deref(), Some("personal:/photos"));
        assert_eq!((keep.whole)("files/notes/a.md"), None);
        assert_eq!((keep.whole)("network/members/did"), Some(String::new()), "a daemon object is kept, by no setting");
        assert_eq!(keep.budget, Some(9));
        let unstated = super::keep(vec![], None);
        assert_eq!((unstated.whole)("files/notes/a.md").as_deref(), Some("default"), "silence keeps everything");
    }

    fn claimed(device: &str, drive: &str) -> Claim {
        Claim { device: device.into(), drive: drive.into() }
    }

    /// **The telling reads the claims and nothing else, and a removed
    /// device's claim counts for nothing** (kotton #171's rules): a device in
    /// the set that claims the drive keeps it whole; a claim by a device no
    /// longer in the set (`c`, removed) is set aside, though nobody deleted
    /// it; a claim for another drive's id says nothing of this one; a drive
    /// recorded with no id is claimed by nobody.
    #[test]
    fn whole_on_reads_claims_only_and_counts_no_removed_device() {
        let devices = vec![("a".to_string(), THIS_DEVICE.to_string()), ("b".to_string(), "laptop".to_string())];
        let claims = vec![claimed("b", FIRST_DRIVE_ID), claimed("c", FIRST_DRIVE_ID), claimed("a", "another-drive")];
        assert_eq!(whole_on(&claims, &devices, Some(FIRST_DRIVE_ID)), ["laptop"]);
        assert_eq!(whole_on(&claims, &devices, Some("another-drive")), [THIS_DEVICE]);
        assert!(whole_on(&claims[1..2], &devices, Some(FIRST_DRIVE_ID)).is_empty(), "a removed device's claim was counted");
        assert!(whole_on(&claims, &devices, None).is_empty());
        assert!(whole_on(&[], &devices, Some(FIRST_DRIVE_ID)).is_empty(), "silence was read as a claim");
    }

    /// A daemon, its records and its machine database, for one person, with a
    /// vault recorded as their drive.
    struct Fixture {
        _temp: tempfile::TempDir,
        rt: crate::DeviceRuntime,
        store: Arc<UserStore>,
        records: SqliteRecordStore,
        db: Arc<SqlitePool>,
    }

    async fn fixture() -> Fixture {
        use crate::users::DeviceUsers as _;
        let temp = tempfile::TempDir::new().unwrap();
        let secrets = Arc::new(kotton_secret::MemorySecrets::new());
        let rt = crate::DeviceRuntime::new_with_secrets(temp.path().to_path_buf(), crate::config::RuntimeConfig::default(), secrets)
            .await
            .unwrap();
        let (_, store) = rt.create_user("alice", "canyon-orbit-velvet-fish-hospital").await.unwrap();
        let records = kotton_record::open::user_record_store(rt.base_dir(), "alice", rt.secrets()).unwrap();
        let db = Arc::new(kotton_record::open_sqlite(&temp.path().join("machine.db")).await.unwrap());
        crate::db::MIGRATOR.run(db.as_ref()).await.unwrap();
        let vault = ed25519_dalek::SigningKey::from_bytes(&[9; 32]).verifying_key().to_bytes();
        let did = kotton_crypto::DidKeyMethod::from_public_key_bytes(&vault).unwrap().to_string();
        kotton_peer::daemon::db::insert_paired_node(&db, "vault", "alice", &did, &vault, "[]", 0, None).await.unwrap();
        kotton_peer::daemon::drives::record(&db, "alice", &vault).await.unwrap();
        Fixture { _temp: temp, rt, store, records, db }
    }

    impl Fixture {
        async fn rows(&self, nsid: &str) -> Vec<Value> {
            Record::new(&self.rt.schema_registry, &self.records).query(nsid, Vec::new(), None, None, None).await.unwrap()
        }
        /// The record store's version of `id`: its revision, which every
        /// write raises (kotton #158), and whether it is a tombstone.
        async fn version(&self, id: &str) -> Option<(i64, bool)> {
            use kotton_record::record_store::RecordStore as _;
            self.records.export_changeset(0).await.unwrap().into_iter().find(|r| r.id == id).map(|r| (r.revision, r.deleted_at.is_some()))
        }
    }

    /// **Settings stay in the device's own database, and none is written to
    /// any drive** (kotton #171's first clause): `pin` at every scope keeps a
    /// row in `pin_settings`, and the person's record store — what rides the
    /// history log to the drive — holds no `sh.kotton.pin` record and no
    /// record but this device's one claim.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn settings_stay_in_the_devices_own_database_and_none_reaches_a_drive() {
        let f = fixture().await;
        let me = "did:key:z6Mkme";
        let set = |scope: PinScope, value: Option<PinValue>| {
            let f = &f;
            async move { super::set(&f.rt.schema_registry, &f.records, &f.store, &f.db, "alice", me, &scope, value).await.unwrap().unwrap() }
        };
        set(PinScope::Default, Some(PinValue::OnDemand)).await;
        set(PinScope::Drive { drive: FIRST_DRIVE_NAME.into() }, Some(PinValue::Whole)).await;
        let read = set(PinScope::Folder { drive: FIRST_DRIVE_NAME.into(), folder: "/raw".into() }, Some(PinValue::OnDemand)).await;
        assert_eq!((read.default, read.exceptions.len()), (PinValue::OnDemand, 2), "{read:?}");
        let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM pin_settings WHERE user_id = 'alice'").fetch_one(f.db.as_ref()).await.unwrap();
        assert_eq!(rows, 3, "a setting is not in the device's own database");
        assert!(f.rows(PIN_NSID).await.is_empty(), "a setting was written to the record log");
        use kotton_record::record_store::RecordStore as _;
        let log = f.records.export_changeset(0).await.unwrap();
        assert!(log.iter().all(|r| r.schema_nsid != PIN_NSID), "a setting rides the log: {log:?}");
        // A folder on demand: the drive is not kept whole, so nothing is claimed.
        assert!(f.rows(CLAIM_NSID).await.is_empty(), "a device keeping a folder on demand claims the drive whole");
    }

    /// **Each device writes only its own claim; a claim is written by `pin …
    /// whole`, withdrawn by a delete at `pin … on-demand`, and written again —
    /// each a new version, so each replicates** (kotton #171's rules, on
    /// #158). Another device's claim, as a pass brought it, is never touched.
    /// And the cost is bounded: a claim already there is not written again.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_device_writes_only_its_own_claim_and_withdraws_it_by_a_delete() {
        let f = fixture().await;
        let me = "did:key:z6Mkme";
        let other = claimed("did:key:z6Mkother", FIRST_DRIVE_ID);
        Record::new(&f.rt.schema_registry, &f.records).insert(CLAIM_NSID, other.to_record()).await.unwrap();
        let mine = claimed(me, FIRST_DRIVE_ID);
        let personal = PinScope::Drive { drive: FIRST_DRIVE_NAME.into() };
        let set = |value: PinValue| {
            let (f, personal) = (&f, personal.clone());
            async move { super::set(&f.rt.schema_registry, &f.records, &f.store, &f.db, "alice", me, &personal, Some(value)).await.unwrap().unwrap() }
        };

        set(PinValue::Whole).await;
        let written = f.version(&mine.record_id()).await.expect("`pin personal whole` wrote no claim");
        assert!(!written.1);
        let all = settings(&f.db, "alice").await.unwrap();
        assert!(!claim(&f.rt.schema_registry, &f.records, &all, me).await.unwrap(), "a claim already there was written again");
        assert_eq!(f.version(&mine.record_id()).await, Some(written), "a claim already there was written again");

        set(PinValue::OnDemand).await;
        let withdrawn = f.version(&mine.record_id()).await.expect("the withdrawn claim left no tombstone");
        assert!(withdrawn.1 && withdrawn.0 > written.0, "the withdrawal is not a delete of a later version: {withdrawn:?}");
        set(PinValue::Whole).await;
        let again = f.version(&mine.record_id()).await.unwrap();
        assert!(!again.1 && again.0 > withdrawn.0, "the claim made again is not a later version: {again:?}");

        let claims = claims(&f.rt.schema_registry, &f.records).await.unwrap();
        assert!(claims.contains(&other), "this device touched another device's claim");
        assert_eq!(claims.iter().filter(|c| c.device == me).count(), 1, "one record per device and drive");
        assert_eq!(f.version(&other.record_id()).await.map(|v| v.1), Some(false));
    }

    /// **A withdrawal is idempotent, so two callers withdrawing at once both
    /// succeed** (what `stating_the_default_does_not_write_over_one_stated_meanwhile`
    /// held of the default before settings left the drive, in its new shape).
    /// `pin … on-demand` runs [`claim`] while a pass runs it too, and the first
    /// `status` after an upgrade runs [`migrate`] while the first pass does:
    /// twenty rounds of each pair at once end with both `Ok` and one tombstone
    /// at a higher revision than the record withdrawn. No lock holds it: a
    /// record this device finds already deleted was deleted by this device.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn two_withdrawals_at_once_both_succeed_and_leave_one_tombstone() {
        let f = fixture().await;
        let me = "did:key:z6Mkme";
        let (registry, records) = (&f.rt.schema_registry, &f.records);
        let mine = claimed(me, FIRST_DRIVE_ID);
        let whole = [at(PinScope::Default, PinValue::Whole)];
        let on_demand = [at(PinScope::Default, PinValue::OnDemand)];
        for round in 0..20 {
            assert!(claim(registry, records, &whole, me).await.unwrap(), "round {round}: no claim was made");
            let made = f.version(&mine.record_id()).await.unwrap();
            let (one, two) = tokio::join!(claim(registry, records, &on_demand, me), claim(registry, records, &on_demand, me));
            assert!(one.is_ok() && two.is_ok(), "round {round}: a withdrawal at once failed: {one:?} {two:?}");
            let left = f.version(&mine.record_id()).await.unwrap();
            assert!(left.1 && left.0 > made.0, "round {round}: no tombstone above {made:?}: {left:?}");

            let id = format!("pin-round-{round}");
            let row = json!({"id": id, "device": me, "scope": "folder", "drive": FIRST_DRIVE_NAME, "folder": format!("/r{round}"), "value": "whole"});
            Record::new(registry, records).insert(PIN_NSID, row).await.unwrap();
            let written = f.version(&id).await.unwrap();
            let (one, two) = tokio::join!(migrate(registry, records, &f.db, "alice", me), migrate(registry, records, &f.db, "alice", me));
            assert!(one.is_ok() && two.is_ok(), "round {round}: a migration at once failed: {one:?} {two:?}");
            let left = f.version(&id).await.unwrap();
            assert!(left.1 && left.0 > written.0, "round {round}: no tombstone above {written:?}: {left:?}");
            let folder = PinScope::Folder { drive: FIRST_DRIVE_NAME.into(), folder: format!("/r{round}") };
            assert!(settings(&f.db, "alice").await.unwrap().iter().any(|s| s.scope == folder), "round {round}: the setting was not moved");
        }
    }

    /// **What kotton #155 wrote is migrated in place**: this device's
    /// `sh.kotton.pin` records move into its own database and are deleted
    /// from the log; another device's are left; a setting stated here since
    /// is not written over; and a second run moves nothing.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_settings_155_wrote_move_into_the_devices_own_database() {
        let f = fixture().await;
        let me = "did:key:z6Mkme";
        let as_155 = |device: &str, scope: &str, drive: Option<&str>, folder: Option<&str>, value: &str| {
            json!({
                "id": format!("pin-{}", blake3::hash(format!("{device}{scope}{drive:?}{folder:?}").as_bytes()).to_hex()),
                "device": device, "scope": scope, "drive": drive, "folder": folder, "value": value,
            })
        };
        let writer = Record::new(&f.rt.schema_registry, &f.records);
        for body in [
            as_155(me, "default", None, None, "on-demand"),
            as_155(me, "folder", Some(FIRST_DRIVE_NAME), Some("/photos"), "whole"),
            as_155(me, "drive", Some(FIRST_DRIVE_NAME), None, "on-demand"),
            as_155("did:key:z6Mkother", "default", None, None, "whole"),
        ] {
            writer.insert(PIN_NSID, body).await.unwrap();
        }
        write(&f.db, "alice", &PinScope::Drive { drive: FIRST_DRIVE_NAME.into() }, Some(PinValue::Whole)).await.unwrap();

        assert_eq!(migrate(&f.rt.schema_registry, &f.records, &f.db, "alice", me).await.unwrap(), 3);
        let mut all = settings(&f.db, "alice").await.unwrap();
        all.sort_by_key(|s| s.scope.said());
        assert_eq!(
            all,
            [
                at(PinScope::Default, PinValue::OnDemand),
                at(PinScope::Drive { drive: FIRST_DRIVE_NAME.into() }, PinValue::Whole),
                at(PinScope::Folder { drive: FIRST_DRIVE_NAME.into(), folder: "/photos".into() }, PinValue::Whole),
            ],
            "the stated setting was written over, or a record was not moved"
        );
        let left = f.rows(PIN_NSID).await;
        assert_eq!(left.len(), 1, "this device's records were not deleted, or another's were: {left:?}");
        assert_eq!(left[0]["device"], "did:key:z6Mkother");
        assert_eq!(migrate(&f.rt.schema_registry, &f.records, &f.db, "alice", me).await.unwrap(), 0, "a second run moved something");
    }

    /// **A folder no setting could keep is never kept**, whatever client
    /// sent it: `pins::set` holds every scope to `PinScope::normalised`, the
    /// normaliser `parse` ends in. `/photos/` is kept as `/photos`, and then
    /// keeps `/photos/x` whole; `photos` and `""` are refused with a sentence
    /// and nothing is written.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_folder_is_held_to_its_form_where_the_setting_is_kept() {
        let f = fixture().await;
        let me = "did:key:z6Mkme";
        let folder = |p: &str| PinScope::Folder { drive: FIRST_DRIVE_NAME.into(), folder: p.into() };
        let set = |scope: PinScope| {
            let f = &f;
            async move { super::set(&f.rt.schema_registry, &f.records, &f.store, &f.db, "alice", me, &scope, Some(PinValue::Whole)).await.unwrap() }
        };
        set(PinScope::Default).await.unwrap();
        write(&f.db, "alice", &PinScope::Default, Some(PinValue::OnDemand)).await.unwrap();
        for bad in ["photos", ""] {
            let refused = set(folder(bad)).await.expect_err("a folder no setting could keep was kept");
            assert!(refused.contains("beginning '/'"), "{bad:?}: {refused}");
        }
        let kept = set(folder("/photos/")).await.unwrap();
        assert_eq!(kept.exceptions.iter().map(|s| s.scope.clone()).collect::<Vec<_>>(), [folder("/photos")]);
        let all = settings(&f.db, "alice").await.unwrap();
        assert_eq!(resolve(&all, FIRST_DRIVE_NAME, Some("/photos/x")).0, PinValue::Whole);
        assert_eq!(resolve(&all, FIRST_DRIVE_NAME, Some("/notes/x")).0, PinValue::OnDemand);
        assert!(write(&f.db, "alice", &PinScope::Default, None).await.is_err(), "the default was told to follow nothing");
    }

    /// **A drive that no longer exists is told of to nobody, and a claim for
    /// it counts for nothing** (kotton #171: a retired drive leaves no claim
    /// behind): the telling walks the drives this device records, never the
    /// claims, so a claim naming an id no recorded drive has — a drive moved
    /// away and retired here — is neither a notice nor a keeper; the first
    /// drive, claimed by nobody, is told of.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_retired_drive_leaves_no_claim_in_the_telling() {
        let f = fixture().await;
        let devices = vec![("did:key:z6Mkme".to_string(), THIS_DEVICE.to_string())];
        let claims = vec![claimed("did:key:z6Mkme", &"ab".repeat(16))];
        let told = notices(&f.db, "alice", &claims, &devices).await.unwrap();
        assert_eq!(told, [PinNotice::NoWholeDevice { drive: FIRST_DRIVE_NAME.into() }], "{told:?}");
        let claims = vec![claimed("did:key:z6Mkme", FIRST_DRIVE_ID)];
        assert!(notices(&f.db, "alice", &claims, &devices).await.unwrap().is_empty());
    }

    /// The record is the claim, field for field — the device and the drive
    /// and nothing else — and its id is the two, so a device claims a drive
    /// once.
    #[test]
    fn a_claim_is_one_record_per_device_and_drive() {
        let c = claimed("did:key:z6Mk", FIRST_DRIVE_ID);
        assert_eq!(Claim::from_record(&c.to_record()).unwrap(), c);
        assert_eq!(c.record_id(), claimed("did:key:z6Mk", FIRST_DRIVE_ID).record_id());
        assert_ne!(c.record_id(), claimed("did:key:other", FIRST_DRIVE_ID).record_id());
        assert_ne!(c.record_id(), claimed("did:key:z6Mk", "another").record_id());
        let schema = kotton_schemas::core::CoreSchema::KeepsWhole.definition();
        let fields: Vec<&str> = schema.fields.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(fields, ["device", "drive"], "a claim carries more than the device and the drive");
        let body = c.to_record();
        let mut keys: Vec<&str> = body.as_object().unwrap().keys().map(String::as_str).collect();
        keys.sort();
        assert_eq!(keys, ["device", "drive", "id"]);
    }
}
