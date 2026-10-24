// SPDX-License-Identifier: AGPL-3.0-or-later
//! **A device's sync rules, each for one of its person's drives** — the
//! `drive_rules` table in the person's own database
//! (`kuserd/migrations_user/0012_drive_rules.sql`), and the three verbs that
//! keep it (`SyncConfigure`, `SyncRuleList`, `SyncRuleRemove`).
//!
//! A rule is kept under the drive itself — the vault's key and the person's
//! tenancy on it, as [`super::drives`] records a drive — with this device's
//! direction for it and whether the background pass syncs it. It names a
//! drive and nothing else: a device replicates to its person's drives and
//! reads from them, and no device is another's target. So a rule is set only
//! for a node the drive record says a drive is reached through; any other
//! node, another of the person's devices among them, is refused by name.
//!
//! Kept by the drive and not the node's label, because a label is a word on
//! this device that can come to name another node, and a rule must not follow
//! it there. [`list`] answers with the label the drive is reached through now.

use kotton_wire::ipc::{SyncDirection, UserResponse};
use kotton_wire::peer::SyncRule;
use sqlx::{Row as _, SqlitePool};
use std::io;
use std::sync::Arc;

fn db_err(e: sqlx::Error) -> io::Error {
    io::Error::other(e.to_string())
}

/// One rule as the table keeps it.
#[derive(Debug, Clone)]
pub struct DriveRule {
    pub vault_key: [u8; 32],
    pub tenancy: String,
    pub direction: Option<SyncDirection>,
    pub watch: bool,
    pub configured_at: i64,
}

fn direction_text(direction: &Option<SyncDirection>) -> Option<&'static str> {
    match direction {
        Some(SyncDirection::Push) => Some("push"),
        Some(SyncDirection::Pull) => Some("pull"),
        None => None,
    }
}

fn direction_of(text: Option<String>) -> Option<SyncDirection> {
    match text.as_deref() {
        Some("push") => Some(SyncDirection::Push),
        Some("pull") => Some(SyncDirection::Pull),
        _ => None,
    }
}

/// Every rule `user_id` keeps on this device, oldest first.
pub async fn rules(user_db: &Arc<SqlitePool>, user_id: &str) -> io::Result<Vec<DriveRule>> {
    let rows = sqlx::query(
        "SELECT vault_key, tenancy, direction, watch, configured_at FROM drive_rules \
         WHERE user_id = ? ORDER BY configured_at, tenancy",
    )
    .bind(user_id)
    .fetch_all(user_db.as_ref())
    .await
    .map_err(db_err)?;
    let mut out = Vec::new();
    for row in rows {
        let key: Vec<u8> = row.get("vault_key");
        let Ok(vault_key) = <[u8; 32]>::try_from(key.as_slice()) else {
            continue;
        };
        out.push(DriveRule {
            vault_key,
            tenancy: row.get("tenancy"),
            direction: direction_of(row.get("direction")),
            watch: row.get::<i64, _>("watch") != 0,
            configured_at: row.get("configured_at"),
        });
    }
    Ok(out)
}

/// The rule `user_id` keeps for the drive at `vault_key` and `tenancy`, if any.
pub fn rule_for<'a>(rules: &'a [DriveRule], drive: &super::drives::Drive) -> Option<&'a DriveRule> {
    rules.iter().find(|r| r.vault_key == drive.vault_key && r.tenancy == drive.tenancy)
}

/// Why a name names no one drive.
enum Unnamed {
    /// A label two of the person's drives are shown under: refused, with the
    /// DIDs that tell them apart, never read as whichever was recorded first.
    Ambiguous(String),
    /// A name no drive carries.
    None(String),
}

impl Unnamed {
    fn said(self) -> String {
        match self {
            Unnamed::Ambiguous(s) | Unnamed::None(s) => s,
        }
    }
}

/// The drive `name` names: the label of the node it is reached through while
/// one drive carries it, that node's DID, or the vault's key in hex. A label
/// keys no row (`super::db`), so two drives may be shown under one; such a
/// label names neither, as `super::db::paired_node_named` refuses it among
/// nodes. `Err` says why there is no one drive.
async fn drive_named(db: &Arc<SqlitePool>, user_id: &str, name: &str) -> io::Result<Result<super::drives::Drive, Unnamed>> {
    let drives = super::drives::list(db, user_id).await?;
    let mut found: Vec<&super::drives::Drive> = Vec::new();
    for d in drives
        .iter()
        .filter(|d| d.node.id == name || d.node.device_did.to_string() == name || hex::encode(d.vault_key) == name)
    {
        if !found.iter().any(|f| f.vault_key == d.vault_key && f.tenancy == d.tenancy) {
            found.push(d);
        }
    }
    match found.as_slice() {
        [one] => return Ok(Ok((*one).clone())),
        [] => {}
        many => {
            let dids: Vec<String> = many.iter().map(|d| d.node.device_did.to_string()).collect();
            return Ok(Err(Unnamed::Ambiguous(format!(
                "'{name}' is the label of {} of your drives ({}); name the one you mean by its DID",
                many.len(),
                dids.join(", ")
            ))));
        }
    }
    let paired = super::db::list_paired_nodes(db, user_id)
        .await?
        .iter()
        .any(|n| n.id == name || n.device_did.to_string() == name);
    Ok(Err(Unnamed::None(if paired {
        format!(
            "'{name}' is not one of your drives: a sync rule names a drive, and a device is not one — \
             devices sync to their drives, never to each other"
        )
    } else {
        format!("'{name}' names none of your drives")
    })))
}

fn rule_said(rule: &DriveRule, drive: &str) -> SyncRule {
    SyncRule {
        drive: drive.to_string(),
        vault_key: hex::encode(rule.vault_key),
        tenancy: rule.tenancy.clone(),
        direction: rule.direction.clone(),
        watch: rule.watch,
        configured_at: rule.configured_at,
    }
}

/// `SyncConfigure`: keep this device's rule for the drive `drive` names.
/// `db` is the machine database, where the drive record is; `user_db` the
/// person's own, where the rule is kept.
pub async fn configure(
    db: &Arc<SqlitePool>,
    user_db: &Arc<SqlitePool>,
    user_id: String,
    drive: String,
    direction: Option<SyncDirection>,
    watch: bool,
) -> io::Result<UserResponse> {
    let found = match drive_named(db, &user_id, &drive).await? {
        Ok(d) => d,
        Err(unnamed) => return Ok(UserResponse::Error { message: unnamed.said() }),
    };
    let rule = DriveRule {
        vault_key: found.vault_key,
        tenancy: found.tenancy.clone(),
        direction,
        watch,
        configured_at: kotton_common::time::now_secs(),
    };
    sqlx::query(
        "INSERT INTO drive_rules (user_id, vault_key, tenancy, direction, watch, configured_at) \
         VALUES (?, ?, ?, ?, ?, ?) \
         ON CONFLICT (user_id, vault_key, tenancy) DO UPDATE SET \
           direction = excluded.direction, watch = excluded.watch, configured_at = excluded.configured_at",
    )
    .bind(&user_id)
    .bind(rule.vault_key.as_slice())
    .bind(&rule.tenancy)
    .bind(direction_text(&rule.direction))
    .bind(rule.watch as i64)
    .bind(rule.configured_at)
    .execute(user_db.as_ref())
    .await
    .map_err(db_err)?;
    Ok(UserResponse::SyncConfigured { rule: rule_said(&rule, &found.node.id) })
}

/// `SyncRuleList`: every rule, each with the label its drive is reached
/// through now — empty for a rule whose drive is no longer recorded here.
pub async fn list(db: &Arc<SqlitePool>, user_db: &Arc<SqlitePool>, user_id: String) -> io::Result<UserResponse> {
    let drives = super::drives::list(db, &user_id).await?;
    let rules = rules(user_db, &user_id)
        .await?
        .iter()
        .map(|r| {
            let label = drives
                .iter()
                .find(|d| d.vault_key == r.vault_key && d.tenancy == r.tenancy)
                .map(|d| d.node.id.as_str())
                .unwrap_or("");
            rule_said(r, label)
        })
        .collect();
    Ok(UserResponse::SyncRuleList { rules })
}

/// `SyncRuleRemove`: drop the rule for the drive `drive` names — by the label
/// it is reached through, or by the vault's key in hex for a rule whose drive
/// is no longer recorded.
pub async fn remove(db: &Arc<SqlitePool>, user_db: &Arc<SqlitePool>, user_id: String, drive: String) -> io::Result<UserResponse> {
    let keyed: Option<(Vec<u8>, Option<String>)> = match drive_named(db, &user_id, &drive).await? {
        Ok(d) => Some((d.vault_key.to_vec(), Some(d.tenancy))),
        Err(Unnamed::Ambiguous(message)) => return Ok(UserResponse::Error { message }),
        Err(Unnamed::None(_)) => hex::decode(&drive).ok().filter(|k| k.len() == 32).map(|k| (k, None)),
    };
    let removed = match keyed {
        Some((key, Some(tenancy))) => sqlx::query("DELETE FROM drive_rules WHERE user_id = ? AND vault_key = ? AND tenancy = ?")
            .bind(&user_id)
            .bind(key)
            .bind(tenancy)
            .execute(user_db.as_ref())
            .await
            .map_err(db_err)?
            .rows_affected(),
        Some((key, None)) => sqlx::query("DELETE FROM drive_rules WHERE user_id = ? AND vault_key = ?")
            .bind(&user_id)
            .bind(key)
            .execute(user_db.as_ref())
            .await
            .map_err(db_err)?
            .rows_affected(),
        None => 0,
    };
    if removed == 0 {
        return Ok(UserResponse::Error { message: format!("no sync rule for '{drive}'") });
    }
    Ok(UserResponse::SyncRuleRemoved)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kotton_schemas::membership::Posture;

    async fn machine_db(dir: &std::path::Path) -> Arc<SqlitePool> {
        let options = sqlx::sqlite::SqliteConnectOptions::new().filename(dir.join("agent.db")).create_if_missing(true);
        let pool = SqlitePool::connect_with(options).await.unwrap();
        sqlx::migrate!("../device/migrations").run(&pool).await.unwrap();
        Arc::new(pool)
    }

    async fn user_db(dir: &std::path::Path) -> Arc<SqlitePool> {
        let options = sqlx::sqlite::SqliteConnectOptions::new().filename(dir.join("user.db")).create_if_missing(true);
        let pool = SqlitePool::connect_with(options).await.unwrap();
        sqlx::raw_sql(include_str!("../../../kuserd/migrations_user/0012_drive_rules.sql"))
            .execute(&pool)
            .await
            .unwrap();
        Arc::new(pool)
    }

    /// A node paired to alice under `seed`'s key, as `posture`.
    async fn paired(db: &Arc<SqlitePool>, id: &str, seed: u8, posture: Posture) -> [u8; 32] {
        let key = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]).verifying_key().to_bytes();
        let did = kotton_crypto::DidKeyMethod::from_public_key_bytes(&key).unwrap();
        super::super::db::insert_paired_node(db, id, "alice", &did.to_string(), &key, "[]", 0, Some(posture.as_str()))
            .await
            .unwrap();
        key
    }

    /// **A rule names a drive**: kept under the vault's key and the tenancy,
    /// with this device's direction and watch, and listed by the label the
    /// drive is reached through.
    #[tokio::test]
    async fn a_rule_is_kept_under_the_drive_with_its_direction() {
        let dir = tempfile::tempdir().unwrap();
        let (db, udb) = (machine_db(dir.path()).await, user_db(dir.path()).await);
        let key = paired(&db, "vault", 9, Posture::BlindStorage).await;
        super::super::drives::record(&db, "alice", &key).await.unwrap();

        let set = configure(&db, &udb, "alice".into(), "vault".into(), Some(SyncDirection::Push), true).await.unwrap();
        let UserResponse::SyncConfigured { rule } = set else { panic!("{set:?}") };
        assert_eq!((rule.drive.as_str(), rule.vault_key.clone(), rule.tenancy.as_str()), ("vault", hex::encode(key), "alice"));
        assert!(matches!(rule.direction, Some(SyncDirection::Push)) && rule.watch);

        let kept = rules(&udb, "alice").await.unwrap();
        assert_eq!(kept.len(), 1);
        assert_eq!((kept[0].vault_key, kept[0].tenancy.as_str()), (key, "alice"));
        // Set again: one rule, the new direction.
        configure(&db, &udb, "alice".into(), "vault".into(), None, false).await.unwrap();
        let kept = rules(&udb, "alice").await.unwrap();
        assert_eq!(kept.len(), 1);
        assert!(kept[0].direction.is_none() && !kept[0].watch);

        let UserResponse::SyncRuleList { rules: listed } = list(&db, &udb, "alice".into()).await.unwrap() else { panic!() };
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].drive, "vault");

        assert!(matches!(remove(&db, &udb, "alice".into(), "vault".into()).await.unwrap(), UserResponse::SyncRuleRemoved));
        assert!(rules(&udb, "alice").await.unwrap().is_empty());
    }

    /// **A rule never names a device**: a paired node the drive record does
    /// not name — another of the person's own devices — is refused by name,
    /// and nothing is kept; and a name nothing pairs is refused too.
    #[tokio::test]
    async fn a_rule_for_a_device_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let (db, udb) = (machine_db(dir.path()).await, user_db(dir.path()).await);
        paired(&db, "phone", 4, Posture::Full).await;
        let said = configure(&db, &udb, "alice".into(), "phone".into(), None, true).await.unwrap();
        match said {
            UserResponse::Error { message } => assert!(message.contains("a device is not one"), "{message}"),
            other => panic!("a rule for a device was kept: {other:?}"),
        }
        assert!(matches!(
            configure(&db, &udb, "alice".into(), "nowhere".into(), None, true).await.unwrap(),
            UserResponse::Error { .. }
        ));
        assert!(rules(&udb, "alice").await.unwrap().is_empty());
    }

    /// A rule whose drive is no longer recorded is listed with no label and
    /// removed by the vault's key.
    #[tokio::test]
    async fn a_rule_outliving_its_drive_is_listed_unnamed_and_removed_by_key() {
        let dir = tempfile::tempdir().unwrap();
        let (db, udb) = (machine_db(dir.path()).await, user_db(dir.path()).await);
        let key = paired(&db, "vault", 9, Posture::BlindStorage).await;
        super::super::drives::record(&db, "alice", &key).await.unwrap();
        configure(&db, &udb, "alice".into(), "vault".into(), None, true).await.unwrap();
        let did = kotton_crypto::DidKeyMethod::from_public_key_bytes(&key).unwrap().to_string();
        assert!(super::super::db::delete_paired_node(&db, "alice", &did).await.unwrap());

        let UserResponse::SyncRuleList { rules: listed } = list(&db, &udb, "alice".into()).await.unwrap() else { panic!() };
        assert_eq!(listed[0].drive, "");
        assert!(matches!(remove(&db, &udb, "alice".into(), hex::encode(key)).await.unwrap(), UserResponse::SyncRuleRemoved));
    }

    /// **A label two drives are shown under names neither** (kotton #99). A
    /// label keys no row, so the person may keep two vaults under `vault`: a
    /// rule set or removed by that label is refused with both DIDs, nothing is
    /// kept, and each drive is still named by its DID.
    #[tokio::test]
    async fn a_label_two_drives_carry_is_refused_with_both_dids() {
        let dir = tempfile::tempdir().unwrap();
        let (db, udb) = (machine_db(dir.path()).await, user_db(dir.path()).await);
        let first = paired(&db, "vault", 9, Posture::BlindStorage).await;
        let second = paired(&db, "vault", 8, Posture::BlindStorage).await;
        for key in [first, second] {
            super::super::drives::record(&db, "alice", &key).await.unwrap();
        }
        let did = |k: &[u8; 32]| kotton_crypto::DidKeyMethod::from_public_key_bytes(k).unwrap().to_string();

        for said in [
            configure(&db, &udb, "alice".into(), "vault".into(), None, true).await.unwrap(),
            remove(&db, &udb, "alice".into(), "vault".into()).await.unwrap(),
        ] {
            let UserResponse::Error { message } = said else { panic!("an ambiguous label was taken: {said:?}") };
            assert!(message.contains(&did(&first)) && message.contains(&did(&second)), "{message}");
        }
        assert!(rules(&udb, "alice").await.unwrap().is_empty(), "a rule was kept under an ambiguous label");

        let set = configure(&db, &udb, "alice".into(), did(&second), None, true).await.unwrap();
        let UserResponse::SyncConfigured { rule } = set else { panic!("{set:?}") };
        assert_eq!(rule.vault_key, hex::encode(second));
    }
}
