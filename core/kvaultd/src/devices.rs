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
//! 3. an admit is later than every change taken for that key (`said_at_ms`,
//!    kept in `tenant_device_changes`), so an admit replayed after a
//!    withdrawal does not put a revoked device back; a withdrawal is always
//!    taken, whatever its time ([`apply`]);
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
    if let Err(why) = accept(ctx.runtime.base_dir(), &ctx.db, &ctx.runtime.paired_keys(), user_id, &change, signature).await {
        return refused(why);
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

/// The whole of the acceptance, conditions 1 to 4 and the write: `base` is
/// where this vault keeps the tenant's key log. `Err` says why it was refused.
pub async fn accept(
    base: &std::path::Path,
    db: &Arc<SqlitePool>,
    paired_keys: &Arc<std::sync::RwLock<std::collections::HashSet<[u8; 32]>>>,
    user_id: &str,
    change: &TenantDeviceChange,
    signature: &[u8],
) -> Result<(), String> {
    // 1. Under the identity, as this vault's copy of its key log has it now.
    let chain = match kotton_identity::kel_store::load_chain(base, user_id) {
        Ok(c) if !c.is_empty() => c,
        Ok(_) => return Err("this drive keeps no key log for the tenant".to_string()),
        Err(e) => return Err(format!("the tenant's key log does not read: {e}")),
    };
    let identity = resolve_current_key(&chain, &LocalArbiter, false)
        .map_err(|e| e.to_string())
        .and_then(|k| VerifyingKey::from_bytes(&k).map_err(|e| e.to_string()))
        .map_err(|e| format!("the tenant's key log does not resolve to a key: {e}"))?;
    let signature = Signature::from_slice(signature).map_err(|_| "the signature is not an Ed25519 signature".to_string())?;
    if identity.verify_strict(&change.signed_bytes(user_id), &signature).is_err() {
        return Err("it is not signed under the tenant's identity".to_string());
    }

    // 2. The DID is the key's.
    let named = Did::parse(&change.device_did)
        .ok()
        .and_then(|d| DidKeyMethod::to_public_key(&d).ok())
        .map(|k| k.to_bytes());
    if named != Some(change.public_key) {
        return Err("the device's DID does not name its key".to_string());
    }

    // 3 and 4, and the write.
    match apply(db, paired_keys, user_id, change).await {
        Ok(taken) => taken,
        Err(e) => Err(e.to_string()),
    }
}

/// Steps 3 and 4 and the write, on the vault's database, in one immediate
/// transaction: the read of the last change and the write that follows it are
/// one step, so two changes to one key cannot both read the same "last".
/// `Ok(Err(_))` is a refusal; `Err(_)` a database that did not answer.
///
/// **A withdrawal always wins.** An admit is taken only when it is later than
/// every change taken for the key; a withdrawal is taken whenever it comes —
/// at the same millisecond as the last admit, or with a clock that stepped
/// back — and records the later of its time and the last, so no admit at or
/// before it can follow. A key removed from the set is refused at its next
/// connection whatever the clocks say; the worst an old withdrawal replayed by
/// one of the person's own devices can do is take a device out, which errs
/// toward refusing.
async fn apply(
    db: &Arc<SqlitePool>,
    paired_keys: &Arc<std::sync::RwLock<std::collections::HashSet<[u8; 32]>>>,
    user_id: &str,
    change: &TenantDeviceChange,
) -> io::Result<Result<(), String>> {
    let mut conn = db.acquire().await.map_err(io::Error::other)?;
    sqlx::query("BEGIN IMMEDIATE").execute(&mut *conn).await.map_err(io::Error::other)?;
    let outcome = apply_in(&mut conn, user_id, change).await;
    let end = if matches!(outcome, Ok(Ok(()))) { "COMMIT" } else { "ROLLBACK" };
    sqlx::query(end).execute(&mut *conn).await.map_err(io::Error::other)?;
    let outcome = outcome?;
    if outcome.is_ok() && change.act == TenantDeviceAct::Admit {
        paired_keys.write().unwrap().insert(change.public_key);
    }
    Ok(outcome)
}

async fn apply_in(
    conn: &mut sqlx::SqliteConnection,
    user_id: &str,
    change: &TenantDeviceChange,
) -> io::Result<Result<(), String>> {
    let said_at = i64::try_from(change.said_at_ms).map_err(io::Error::other)?;
    let key = change.public_key.as_slice();
    let last: Option<i64> =
        sqlx::query("SELECT said_at FROM tenant_device_changes WHERE user_id = ? AND public_key = ?")
            .bind(user_id)
            .bind(key)
            .fetch_optional(&mut *conn)
            .await
            .map_err(io::Error::other)?
            .map(|r| r.get("said_at"));
    let recorded = match change.act {
        TenantDeviceAct::Admit => {
            if last.is_some_and(|l| said_at <= l) {
                return Ok(Err("an admit no later than a change already taken for this key".to_string()));
            }
            let operator = sqlx::query("SELECT 1 FROM operator_key WHERE public_key = ? LIMIT 1")
                .bind(key)
                .fetch_optional(&mut *conn)
                .await
                .map_err(io::Error::other)?;
            if operator.is_some() {
                return Ok(Err("the key is this vault's operator credential".to_string()));
            }
            let held: Option<String> = sqlx::query("SELECT user_id FROM paired_nodes WHERE public_key = ? LIMIT 1")
                .bind(key)
                .fetch_optional(&mut *conn)
                .await
                .map_err(io::Error::other)?
                .map(|r| r.get("user_id"));
            match held {
                Some(held) if held != user_id => {
                    return Ok(Err("the key is paired here to another tenant".to_string()));
                }
                Some(_) => {}
                // The row the enrolment writes, keyed by the DID rather than
                // a name the device chose.
                None => {
                    sqlx::query(
                        "INSERT INTO paired_nodes \
                         (id, user_id, device_did, public_key, addresses, paired_at, posture, relay_url) \
                         VALUES (?, ?, ?, ?, '[]', ?, ?, NULL)",
                    )
                    .bind(&change.device_did)
                    .bind(user_id)
                    .bind(&change.device_did)
                    .bind(key)
                    .bind(kotton_common::time::now_secs())
                    .bind(kotton_schemas::membership::Posture::Full.as_str())
                    .execute(&mut *conn)
                    .await
                    .map_err(io::Error::other)?;
                }
            }
            said_at
        }
        TenantDeviceAct::Withdraw => {
            sqlx::query("DELETE FROM paired_nodes WHERE user_id = ? AND public_key = ?")
                .bind(user_id)
                .bind(key)
                .execute(&mut *conn)
                .await
                .map_err(io::Error::other)?;
            last.map_or(said_at, |l| l.max(said_at))
        }
    };
    sqlx::query(
        "INSERT INTO tenant_device_changes (user_id, public_key, said_at) VALUES (?, ?, ?)
         ON CONFLICT(user_id, public_key) DO UPDATE SET said_at = excluded.said_at",
    )
    .bind(user_id)
    .bind(key)
    .bind(recorded)
    .execute(&mut *conn)
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
        TenantDeviceChange { act, device_did: format!("did:key:z{}", key[0]), public_key: key, said_at_ms: said_at }
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
        let same_time = apply(&db, &keys, "alice", &a_change(TenantDeviceAct::Admit, key, 20)).await.unwrap();
        assert!(same_time.is_err(), "an admit at the same time as the last change was taken");
    }

    /// **A withdrawal always wins**: one at the same millisecond as the admit,
    /// or older than it (a clock that stepped back), is taken and takes the
    /// device out; and no admit at or before the later of the two follows it.
    #[tokio::test]
    async fn a_withdrawal_is_taken_at_the_same_time_as_the_admit_or_older() {
        let db = a_vault_db().await;
        let keys = Arc::new(RwLock::new(HashSet::new()));
        for (key, withdrawn_at) in [([6u8; 32], 50u64), ([7u8; 32], 40u64)] {
            apply(&db, &keys, "alice", &a_change(TenantDeviceAct::Admit, key, 50)).await.unwrap().unwrap();
            apply(&db, &keys, "alice", &a_change(TenantDeviceAct::Withdraw, key, withdrawn_at))
                .await
                .unwrap()
                .unwrap_or_else(|why| panic!("a withdrawal at {withdrawn_at} after an admit at 50 was refused: {why}"));
            assert!(!paired(&db, "alice", &key).await, "the withdrawn device is still paired");
            let again = apply(&db, &keys, "alice", &a_change(TenantDeviceAct::Admit, key, 50)).await.unwrap();
            assert!(again.is_err(), "an admit at 50 followed the withdrawal");
            apply(&db, &keys, "alice", &a_change(TenantDeviceAct::Admit, key, 51)).await.unwrap().unwrap();
            assert!(paired(&db, "alice", &key).await, "a later admit is taken");
        }
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

    /// A tenant whose identity is `identity`, with its key log at `base` as
    /// the vault keeps it; and a change signed under it.
    fn a_tenant_at(base: &std::path::Path, identity: &ed25519_dalek::SigningKey) {
        let inception = kotton_crypto::kel_verify::build_fresh_inception(identity);
        kotton_identity::kel_store::save_chain(base, "alice", &[inception]).expect("the key log");
    }

    fn signed(identity: &ed25519_dalek::SigningKey, change: &TenantDeviceChange) -> Vec<u8> {
        use ed25519_dalek::Signer as _;
        identity.sign(&change.signed_bytes("alice")).to_bytes().to_vec()
    }

    fn a_device(seed: u8) -> ([u8; 32], String) {
        let key = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]).verifying_key();
        (key.to_bytes(), DidKeyMethod::from_public_key(&key).to_string())
    }

    /// Through the whole acceptance: an admit under the identity, for a key
    /// its DID names, is taken; the same under any other key is refused.
    #[tokio::test]
    async fn an_admit_is_taken_only_under_the_identity() {
        let base = tempfile::tempdir().unwrap();
        let identity = ed25519_dalek::SigningKey::from_bytes(&[1; 32]);
        a_tenant_at(base.path(), &identity);
        let db = a_vault_db().await;
        let keys = Arc::new(RwLock::new(HashSet::new()));
        let (key, did) = a_device(2);
        let change = TenantDeviceChange { act: TenantDeviceAct::Admit, device_did: did, public_key: key, said_at_ms: 1 };

        let forged = signed(&ed25519_dalek::SigningKey::from_bytes(&[3; 32]), &change);
        let why = accept(base.path(), &db, &keys, "alice", &change, &forged).await.unwrap_err();
        assert!(why.contains("not signed under the tenant's identity"), "{why}");
        assert!(!paired(&db, "alice", &key).await);

        accept(base.path(), &db, &keys, "alice", &change, &signed(&identity, &change)).await.unwrap();
        assert!(paired(&db, "alice", &key).await);
    }

    /// **Condition 2, through the whole acceptance**: an admit the identity
    /// signed, whose DID names another key, is refused by name.
    #[tokio::test]
    async fn an_admit_whose_did_does_not_name_its_key_is_refused() {
        let base = tempfile::tempdir().unwrap();
        let identity = ed25519_dalek::SigningKey::from_bytes(&[1; 32]);
        a_tenant_at(base.path(), &identity);
        let db = a_vault_db().await;
        let keys = Arc::new(RwLock::new(HashSet::new()));
        let (key, _) = a_device(2);
        let (_, another_did) = a_device(4);
        let change = TenantDeviceChange { act: TenantDeviceAct::Admit, device_did: another_did, public_key: key, said_at_ms: 1 };
        let why = accept(base.path(), &db, &keys, "alice", &change, &signed(&identity, &change)).await.unwrap_err();
        assert!(why.contains("the device's DID does not name its key"), "{why}");
        assert!(!paired(&db, "alice", &key).await);
        assert!(!keys.read().unwrap().contains(&key));
    }

    /// **The operator's half of condition 4, through the whole acceptance**:
    /// the vault's operator credential is not admitted as a tenant's device,
    /// though the identity signed for it and its DID names it.
    #[tokio::test]
    async fn an_admit_of_the_operators_key_is_refused() {
        let base = tempfile::tempdir().unwrap();
        let identity = ed25519_dalek::SigningKey::from_bytes(&[1; 32]);
        a_tenant_at(base.path(), &identity);
        let db = a_vault_db().await;
        let keys = Arc::new(RwLock::new(HashSet::new()));
        let (operator, did) = a_device(5);
        kotton_peer::daemon::db::enrol_operator_key(&db, &operator).await.unwrap();
        let change = TenantDeviceChange { act: TenantDeviceAct::Admit, device_did: did, public_key: operator, said_at_ms: 1 };
        let why = accept(base.path(), &db, &keys, "alice", &change, &signed(&identity, &change)).await.unwrap_err();
        assert!(why.contains("the key is this vault's operator credential"), "{why}");
        assert!(!paired(&db, "alice", &operator).await);
    }
}
