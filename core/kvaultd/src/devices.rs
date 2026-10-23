// SPDX-License-Identifier: AGPL-3.0-or-later
//! A tenant's other devices, introduced to the drive under the identity's
//! signature (`TenantDevice`): pairing introduces a device's key to the set a
//! drive admits.
//!
//! A vault holds no data keys, so it cannot read the person's member list, and
//! the enrolment handshake leaves it one row for the tenant: the device that ran
//! it. Proof against the identity's key log admits only the key the log's tip
//! names (`admits_device`), and a device that joined the person holds a key
//! share, not that key. Without this verb every device but the first is a
//! stranger at the person's own drive.
//!
//! **What is taken, and from whom.** A [`TenantDeviceChange`] arrives only on a
//! connection whose standing to the pool is `Paired` (the table in
//! `crate::peer`), and is taken only when:
//!
//! 1. its signature verifies under the identity's current key, replayed from the
//!    key log this vault keeps for the tenant — so a device the vault admits,
//!    but which does not hold the identity, introduces nobody;
//! 2. its `device_did` names its `public_key`;
//! 3. it is later than the last change taken for that key (`said_at`, kept in
//!    `tenant_device_changes`), so an admit replayed after a withdrawal does
//!    not put a revoked device back;
//! 4. an admit's key is no other tenant's here and not the operator's: nothing
//!    joins across tenants.
//!
//! An admit writes the row the enrolment writes — `paired_nodes`, under the
//! tenant, posture `full` — keyed by the device's DID rather than a name it
//! chose, and admits the key at the handshake. A withdrawal deletes the key's
//! row for the tenant and recomputes the allowlist from what is left, as a
//! landlord's drop does (`crate::tenancy`). Both tables carry `user_id`, so a
//! drop sweeps them with the rest.
//!
//! **What the landlord learns:** one more row per device, the count
//! `kvaultd tenants` prints, which it learns anyway from connections. No name a
//! device chose, and nothing that joins one tenant's devices to another's.
//!
//! **The way back.** When the protocol's handshake lands, a drive checks a
//! device against the identity's key log itself, and this verb becomes that
//! log's publication rather than the vault's own list.

use crate::peer::PeerContext;
use ed25519_dalek::{Signature, VerifyingKey};
use kotton_crypto::did::DidKeyMethod;
use kotton_crypto::kel_verify::{resolve_current_key, LocalArbiter};
use kotton_wire::did::Did;
use kotton_wire::ipc::{TenantDeviceAct, TenantDeviceChange, UserResponse};
use sqlx::{Row as _, SqlitePool};
use std::io;
use std::sync::Arc;

/// The table that orders a tenant's changes to one key.
pub async fn init(db: &SqlitePool) -> io::Result<()> {
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS tenant_device_changes (
            user_id TEXT NOT NULL,
            public_key BLOB NOT NULL,
            said_at INTEGER NOT NULL,
            PRIMARY KEY (user_id, public_key)
        )",
    )
    .execute(db)
    .await
    .map_err(io::Error::other)?;
    Ok(())
}

fn refused(why: impl std::fmt::Display) -> UserResponse {
    UserResponse::Error {
        message: format!("this drive did not take the change to the tenant's devices: {why}"),
    }
}

/// Take `change` to `user_id`'s devices here, if the identity said it. The
/// caller has found the connection `Paired` to `user_id`'s pool.
pub async fn change(ctx: &PeerContext, user_id: &str, change: TenantDeviceChange, signature: &[u8]) -> UserResponse {
    // 1. Under the identity, as this vault's copy of its key log has it now.
    let chain = match kotton_identity::kel_store::load_chain(ctx.runtime.base_dir(), user_id) {
        Ok(c) if !c.is_empty() => c,
        Ok(_) => return refused("this drive keeps no key log for the tenant"),
        Err(e) => return refused(format!("the tenant's key log does not read: {e}")),
    };
    let identity = match resolve_current_key(&chain, &LocalArbiter, false)
        .map_err(|e| e.to_string())
        .and_then(|k| VerifyingKey::from_bytes(&k).map_err(|e| e.to_string()))
    {
        Ok(k) => k,
        Err(e) => return refused(format!("the tenant's key log does not resolve to a key: {e}")),
    };
    let Ok(signature) = Signature::from_slice(signature) else {
        return refused("the signature is not an Ed25519 signature");
    };
    if identity.verify_strict(&change.signed_bytes(user_id), &signature).is_err() {
        return refused("it is not signed under the tenant's identity");
    }

    // 2. The DID is the key's.
    let named = Did::parse(&change.device_did)
        .ok()
        .and_then(|d| DidKeyMethod::to_public_key(&d).ok())
        .map(|k| k.to_bytes());
    if named != Some(change.public_key) {
        return refused("the device's DID does not name its key");
    }

    match apply(&ctx.db, &ctx.runtime.paired_keys(), user_id, &change).await {
        Ok(Ok(())) => {}
        Ok(Err(why)) => return refused(why),
        Err(e) => return refused(e),
    }
    if change.act == TenantDeviceAct::Withdraw {
        // Recomputed from what is left, never subtracted, as a drop does.
        let stores: Vec<(String, Arc<dyn kotton_peer::membership::MemberStore>)> = ctx
            .pools
            .all()
            .into_iter()
            .map(|(id, s)| (id, s as Arc<dyn kotton_peer::membership::MemberStore>))
            .collect();
        kotton_peer::daemon::nodes::reproject_allowlist(&stores, &ctx.db, &ctx.runtime.paired_keys()).await;
    }
    tracing::info!(user_id, device = %change.device_did, act = ?change.act, "took a change to a tenant's devices");
    UserResponse::Ok
}

/// Steps 3 and 4 and the write, on the vault's database. `Ok(Err(_))` is a
/// refusal; `Err(_)` a database that did not answer.
async fn apply(
    db: &Arc<SqlitePool>,
    paired_keys: &Arc<std::sync::RwLock<std::collections::HashSet<[u8; 32]>>>,
    user_id: &str,
    change: &TenantDeviceChange,
) -> io::Result<Result<(), String>> {
    let said_at = i64::try_from(change.said_at).map_err(io::Error::other)?;
    let last: Option<i64> =
        sqlx::query("SELECT said_at FROM tenant_device_changes WHERE user_id = ? AND public_key = ?")
            .bind(user_id)
            .bind(change.public_key.as_slice())
            .fetch_optional(db.as_ref())
            .await
            .map_err(io::Error::other)?
            .map(|r| r.get("said_at"));
    if last.is_some_and(|l| said_at <= l) {
        return Ok(Err("a change to this key no earlier than it was already taken".to_string()));
    }
    match change.act {
        TenantDeviceAct::Admit => {
            if kotton_peer::daemon::db::is_operator_key(db, &change.public_key).await? {
                return Ok(Err("the key is this vault's operator credential".to_string()));
            }
            if let Some((held, _)) = kotton_peer::daemon::db::paired_node_for_pubkey(db, &change.public_key).await? {
                if held != user_id {
                    return Ok(Err("the key is paired here to another tenant".to_string()));
                }
            } else {
                let now = kotton_common::time::now_secs();
                kotton_peer::daemon::db::insert_paired_node(
                    db,
                    &change.device_did,
                    user_id,
                    &change.device_did,
                    &change.public_key,
                    "[]",
                    now,
                    Some(kotton_schemas::membership::Posture::Full.as_str()),
                )
                .await?;
            }
            paired_keys.write().unwrap().insert(change.public_key);
        }
        TenantDeviceAct::Withdraw => {
            kotton_peer::daemon::db::delete_paired_key(db, user_id, &change.public_key).await?;
        }
    }
    sqlx::query(
        "INSERT INTO tenant_device_changes (user_id, public_key, said_at) VALUES (?, ?, ?)
         ON CONFLICT(user_id, public_key) DO UPDATE SET said_at = excluded.said_at",
    )
    .bind(user_id)
    .bind(change.public_key.as_slice())
    .bind(said_at)
    .execute(db.as_ref())
    .await
    .map_err(io::Error::other)?;
    Ok(Ok(()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::sync::RwLock;

    async fn a_vault_db() -> Arc<SqlitePool> {
        let db = Arc::new(SqlitePool::connect("sqlite::memory:").await.expect("db"));
        kotton_device::db::MIGRATOR.run(db.as_ref()).await.expect("migrations");
        init(&db).await.expect("tenant_device_changes");
        db
    }

    fn a_change(act: TenantDeviceAct, key: [u8; 32], said_at: u64) -> TenantDeviceChange {
        TenantDeviceChange { act, device_did: format!("did:key:z{}", key[0]), public_key: key, said_at }
    }

    async fn paired(db: &Arc<SqlitePool>, user: &str, key: &[u8; 32]) -> bool {
        kotton_peer::daemon::db::is_pubkey_paired_to_user(db, key, user).await.unwrap()
    }

    /// An admit writes the tenant's row and admits the key at the handshake; a
    /// later withdrawal deletes the row.
    #[tokio::test]
    async fn an_admitted_key_is_paired_to_the_tenant_and_a_withdrawn_one_is_not() {
        let db = a_vault_db().await;
        let keys = Arc::new(RwLock::new(HashSet::new()));
        let key = [3u8; 32];
        apply(&db, &keys, "alice", &a_change(TenantDeviceAct::Admit, key, 10)).await.unwrap().unwrap();
        assert!(paired(&db, "alice", &key).await);
        assert!(keys.read().unwrap().contains(&key));
        apply(&db, &keys, "alice", &a_change(TenantDeviceAct::Withdraw, key, 11)).await.unwrap().unwrap();
        assert!(!paired(&db, "alice", &key).await);
    }

    /// **An admit replayed after a withdrawal does not put the device back**:
    /// a change no later than the last taken for the key is refused.
    #[tokio::test]
    async fn a_change_no_later_than_the_last_for_its_key_is_refused() {
        let db = a_vault_db().await;
        let keys = Arc::new(RwLock::new(HashSet::new()));
        let key = [4u8; 32];
        let admit = a_change(TenantDeviceAct::Admit, key, 10);
        apply(&db, &keys, "alice", &admit).await.unwrap().unwrap();
        apply(&db, &keys, "alice", &a_change(TenantDeviceAct::Withdraw, key, 20)).await.unwrap().unwrap();
        let replayed = apply(&db, &keys, "alice", &admit).await.unwrap();
        assert!(replayed.is_err(), "the replayed admit was taken");
        assert!(!paired(&db, "alice", &key).await, "the withdrawn device is back");
        let same_second = apply(&db, &keys, "alice", &a_change(TenantDeviceAct::Admit, key, 20)).await.unwrap();
        assert!(same_second.is_err(), "a change at the same second as the last was taken");
    }

    /// **Nothing joins across tenants**: a key paired to one tenant is not
    /// admitted for another.
    #[tokio::test]
    async fn a_key_paired_to_another_tenant_is_not_admitted() {
        let db = a_vault_db().await;
        let keys = Arc::new(RwLock::new(HashSet::new()));
        let key = [5u8; 32];
        kotton_peer::daemon::db::insert_paired_node(&db, "bobs-laptop", "bob", "did:key:zBob", &key, "[]", 0, Some("full"))
            .await
            .unwrap();
        let taken = apply(&db, &keys, "alice", &a_change(TenantDeviceAct::Admit, key, 1)).await.unwrap();
        assert!(taken.is_err(), "bob's key was admitted for alice");
        assert!(!paired(&db, "alice", &key).await);
        assert!(paired(&db, "bob", &key).await, "bob's row was disturbed");
    }
}
