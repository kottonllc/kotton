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
//! 2. its `device_did` names its `public_key`. The decode holds the Ed25519 rule
//!    (`kotton_crypto::did`), so an admit's key is one the rule admits. A
//!    withdrawal whose DID names no key is of a row an earlier build stored
//!    under bytes the rule refuses: it is matched by what is stored, the
//!    tenant's row under that DID and those bytes, and not through the decode;
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

use kotton_record::immediate::Immediate;
use crate::peer::PeerContext;
use kotton_crypto::ed25519::Signature;
use kotton_crypto::ed25519::VerifyingKey;
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
    paired_keys: &Arc<std::sync::RwLock<std::collections::HashSet<VerifyingKey>>>,
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
        .map_err(|e| format!("the tenant's key log does not resolve to a key: {e}"))?;
    let signature = Signature::from_slice(signature).map_err(|_| "the signature is not an Ed25519 signature".to_string())?;
    if identity.verify(&change.signed_bytes(user_id), &signature).is_err() {
        return Err("it is not signed under the tenant's identity".to_string());
    }

    // 2. The DID is the key's. The decode holds the Ed25519 rule, so the key it
    // gives is constructed, once, and handed to `apply`; bytes the rule refuses
    // name no key, and an admit under them is refused as a DID that names none.
    // A withdrawal whose DID names no key is matched as stored (`Stored`).
    let named = Did::parse(&change.device_did).ok().and_then(|d| DidKeyMethod::to_public_key(&d).ok());
    let taken = match (change.act, named) {
        (TenantDeviceAct::Admit, Some(key)) if key.as_bytes() == &change.public_key => Some(Taken::Admit {
            key,
            device_did: &change.device_did,
            said_at_ms: change.said_at_ms,
        }),
        (TenantDeviceAct::Withdraw, Some(key)) if key.as_bytes() == &change.public_key => {
            Some(Taken::Withdraw { public_key: change.public_key, said_at_ms: change.said_at_ms, stored: None })
        }
        (TenantDeviceAct::Withdraw, None) => Some(Taken::Withdraw {
            public_key: change.public_key,
            said_at_ms: change.said_at_ms,
            stored: Some(&change.device_did),
        }),
        _ => None,
    };
    let Some(taken) = taken else {
        return Err("the device's DID does not name its key".to_string());
    };

    // 3 and 4, and the write.
    match apply(db, paired_keys, user_id, taken).await {
        Ok(taken) => taken,
        Err(e) => Err(e.to_string()),
    }
}

/// A change `accept` has taken through condition 2, in the form the write needs.
/// An admit carries the key `accept` constructed and no raw bytes: its row and its
/// allowlist entry are both that key, and an admit without its key cannot be
/// written. A withdraw carries the stored bytes, which the Ed25519 rule does not
/// hold, so that it can remove a row whatever they are; it never enters the
/// allowlist. `stored` is `None` where the DID named those bytes as a key, and
/// the DID as stored where it names no key: then only the tenant's row under
/// that DID and those bytes is removed, and no change is recorded under bytes
/// that are no key.
#[derive(Clone, Copy)]
enum Taken<'a> {
    Admit { key: VerifyingKey, device_did: &'a str, said_at_ms: u64 },
    Withdraw { public_key: [u8; 32], said_at_ms: u64, stored: Option<&'a str> },
}

impl Taken<'_> {
    fn public_key(&self) -> &[u8; 32] {
        match self {
            Taken::Admit { key, .. } => key.as_bytes(),
            Taken::Withdraw { public_key, .. } => public_key,
        }
    }

    fn said_at_ms(&self) -> u64 {
        match self {
            Taken::Admit { said_at_ms, .. } | Taken::Withdraw { said_at_ms, .. } => *said_at_ms,
        }
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
    paired_keys: &Arc<std::sync::RwLock<std::collections::HashSet<VerifyingKey>>>,
    user_id: &str,
    taken: Taken<'_>,
) -> io::Result<Result<(), String>> {
    apply_ending(db, paired_keys, user_id, taken, None).await
}

/// [`apply`], with the statement that ends the transaction given: `None` is
/// `COMMIT` on a change taken and `ROLLBACK` otherwise. A test gives one that
/// fails, to hold that a failed end returns no locked connection to the pool.
async fn apply_ending(
    db: &Arc<SqlitePool>,
    paired_keys: &Arc<std::sync::RwLock<std::collections::HashSet<VerifyingKey>>>,
    user_id: &str,
    taken: Taken<'_>,
    end: Option<&str>,
) -> io::Result<Result<(), String>> {
    let mut tx = Immediate::begin(db).await?;
    let outcome = apply_in(tx.conn(), user_id, taken).await;
    let done = matches!(outcome, Ok(Ok(())));
    tx.end(end.unwrap_or(if done { "COMMIT" } else { "ROLLBACK" })).await?;
    let outcome = outcome?;
    // The key enters the allowlist as the key `accept` constructed at condition 2.
    if let (true, Taken::Admit { key, .. }) = (outcome.is_ok(), taken) {
        paired_keys.write().unwrap().insert(key);
    }
    Ok(outcome)
}

async fn apply_in(
    conn: &mut sqlx::SqliteConnection,
    user_id: &str,
    taken: Taken<'_>,
) -> io::Result<Result<(), String>> {
    let said_at = i64::try_from(taken.said_at_ms()).map_err(io::Error::other)?;
    let key = taken.public_key().as_slice();
    // A row an earlier build stored under bytes that name no key, removed by
    // what is stored. Nothing is recorded under those bytes: no admit can be
    // taken under them for a record to order.
    if let Taken::Withdraw { stored: Some(device_did), .. } = taken {
        let removed = sqlx::query("DELETE FROM paired_nodes WHERE user_id = ? AND public_key = ? AND device_did = ?")
            .bind(user_id)
            .bind(key)
            .bind(device_did)
            .execute(&mut *conn)
            .await
            .map_err(io::Error::other)?
            .rows_affected();
        if removed == 0 {
            return Ok(Err("the device's DID names no key, and no row of the tenant's is stored under it".to_string()));
        }
        return Ok(Ok(()));
    }
    let last: Option<i64> =
        sqlx::query("SELECT said_at FROM tenant_device_changes WHERE user_id = ? AND public_key = ?")
            .bind(user_id)
            .bind(key)
            .fetch_optional(&mut *conn)
            .await
            .map_err(io::Error::other)?
            .map(|r| r.get("said_at"));
    let recorded = match taken {
        Taken::Admit { device_did, .. } => {
            if last.is_some_and(|l| said_at <= l) {
                return Ok(Err("an admit no later than a change already taken for this key".to_string()));
            }
            // Not redundant with the handshake deciding the operator first:
            // that covers the key while it is the operator's. A tenant's row
            // for it would outlive the credential, and once the landlord
            // revoked the key it would stand as that tenant's device.
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
                    .bind(device_did)
                    .bind(user_id)
                    .bind(device_did)
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
        Taken::Withdraw { .. } => {
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

    /// `apply` on a change as `accept` forms it, from a real key (`a_device`). After
    /// a taken admit the allowlist holds the key of the row just written; after a
    /// taken withdraw it gained none.
    async fn apply_change(
        db: &Arc<SqlitePool>,
        keys: &Arc<RwLock<HashSet<VerifyingKey>>>,
        user: &str,
        change: &TenantDeviceChange,
    ) -> io::Result<Result<(), String>> {
        let taken = match change.act {
            TenantDeviceAct::Admit => Taken::Admit {
                key: VerifyingKey::from_bytes(&change.public_key).expect("a fixture admit is a key the rule admits"),
                device_did: &change.device_did,
                said_at_ms: change.said_at_ms,
            },
            TenantDeviceAct::Withdraw => Taken::Withdraw { public_key: change.public_key, said_at_ms: change.said_at_ms, stored: None },
        };
        let before = keys.read().unwrap().clone();
        let outcome = apply(db, keys, user, taken).await;
        if matches!(outcome, Ok(Ok(()))) {
            match taken {
                Taken::Admit { device_did, .. } => {
                    let row: Vec<u8> = sqlx::query("SELECT public_key FROM paired_nodes WHERE user_id = ? AND device_did = ?")
                        .bind(user)
                        .bind(device_did)
                        .fetch_one(db.as_ref())
                        .await
                        .unwrap()
                        .get("public_key");
                    let row_key = VerifyingKey::from_bytes(&row.try_into().expect("32 bytes")).unwrap();
                    assert!(keys.read().unwrap().contains(&row_key), "a taken admit did not admit the key of its row");
                }
                Taken::Withdraw { .. } => {
                    assert_eq!(*keys.read().unwrap(), before, "a taken withdraw changed the allowlist");
                }
            }
        }
        outcome
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
        let (key, _) = a_device(3);
        apply_change(&db, &keys, "alice", &a_change(TenantDeviceAct::Admit, key, 10)).await.unwrap().unwrap();
        assert!(paired(&db, "alice", &key).await);
        assert!(keys.read().unwrap().contains(&VerifyingKey::from_bytes(&key).unwrap()));
        apply_change(&db, &keys, "alice", &a_change(TenantDeviceAct::Withdraw, key, 11)).await.unwrap().unwrap();
        assert!(!paired(&db, "alice", &key).await);
    }

    /// **An admit replayed after a withdrawal does not put the device back**:
    /// a change no later than the last taken for the key is refused.
    #[tokio::test]
    async fn a_change_no_later_than_the_last_for_its_key_is_refused() {
        let db = a_vault_db().await;
        let keys = Arc::new(RwLock::new(HashSet::new()));
        let (key, _) = a_device(4);
        let admit = a_change(TenantDeviceAct::Admit, key, 10);
        apply_change(&db, &keys, "alice", &admit).await.unwrap().unwrap();
        apply_change(&db, &keys, "alice", &a_change(TenantDeviceAct::Withdraw, key, 20)).await.unwrap().unwrap();
        let replayed = apply_change(&db, &keys, "alice", &admit).await.unwrap();
        assert!(replayed.is_err(), "the replayed admit was taken");
        assert!(!paired(&db, "alice", &key).await, "the withdrawn device is back");
        let same_time = apply_change(&db, &keys, "alice", &a_change(TenantDeviceAct::Admit, key, 20)).await.unwrap();
        assert!(same_time.is_err(), "an admit at the same time as the last change was taken");
    }

    /// **A withdrawal always wins**: one at the same millisecond as the admit,
    /// or older than it (a clock that stepped back), is taken and takes the
    /// device out; and no admit at or before the later of the two follows it.
    #[tokio::test]
    async fn a_withdrawal_is_taken_at_the_same_time_as_the_admit_or_older() {
        let db = a_vault_db().await;
        let keys = Arc::new(RwLock::new(HashSet::new()));
        for (key, withdrawn_at) in [(a_device(6).0, 50u64), (a_device(7).0, 40u64)] {
            apply_change(&db, &keys, "alice", &a_change(TenantDeviceAct::Admit, key, 50)).await.unwrap().unwrap();
            apply_change(&db, &keys, "alice", &a_change(TenantDeviceAct::Withdraw, key, withdrawn_at))
                .await
                .unwrap()
                .unwrap_or_else(|why| panic!("a withdrawal at {withdrawn_at} after an admit at 50 was refused: {why}"));
            assert!(!paired(&db, "alice", &key).await, "the withdrawn device is still paired");
            let again = apply_change(&db, &keys, "alice", &a_change(TenantDeviceAct::Admit, key, 50)).await.unwrap();
            assert!(again.is_err(), "an admit at 50 followed the withdrawal");
            apply_change(&db, &keys, "alice", &a_change(TenantDeviceAct::Admit, key, 51)).await.unwrap().unwrap();
            assert!(paired(&db, "alice", &key).await, "a later admit is taken");
        }
    }

    /// **Nothing joins across tenants**: a key paired to one tenant is not
    /// admitted for another.
    #[tokio::test]
    async fn a_key_paired_to_another_tenant_is_not_admitted() {
        let db = a_vault_db().await;
        let keys = Arc::new(RwLock::new(HashSet::new()));
        let (key, _) = a_device(5);
        kotton_peer::daemon::db::insert_paired_node(&db, "bobs-laptop", "bob", "did:key:zBob", &key, "[]", 0, Some("full"))
            .await
            .unwrap();
        let taken = apply_change(&db, &keys, "alice", &a_change(TenantDeviceAct::Admit, key, 1)).await.unwrap();
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
        let key = kotton_crypto::ed25519::verifying_key(&ed25519_dalek::SigningKey::from_bytes(&[seed; 32]));
        (*key.as_bytes(), DidKeyMethod::from_public_key(&key).to_string())
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
        assert!(keys.read().unwrap().contains(&VerifyingKey::from_bytes(&key).unwrap()), "an admit taken did not admit the key");
    }

    /// Through the whole acceptance: a non-canonical signature by the identity, in
    /// either form, is refused, and the canonical one over the same change is taken.
    #[tokio::test]
    async fn an_admit_with_a_non_canonical_signature_is_refused() {
        let base = tempfile::tempdir().unwrap();
        let identity = ed25519_dalek::SigningKey::from_bytes(&[1; 32]);
        a_tenant_at(base.path(), &identity);
        let db = a_vault_db().await;
        let keys = Arc::new(RwLock::new(HashSet::new()));
        let (key, did) = a_device(2);
        let change = TenantDeviceChange { act: TenantDeviceAct::Admit, device_did: did, public_key: key, said_at_ms: 1 };

        for sig in kotton_crypto::ed25519::refused::non_canonical(&identity, &change.signed_bytes("alice")) {
            let why = accept(base.path(), &db, &keys, "alice", &change, &sig.to_bytes()).await.unwrap_err();
            assert!(why.contains("not signed under the tenant's identity"), "{why}");
            assert!(!paired(&db, "alice", &key).await);
        }

        accept(base.path(), &db, &keys, "alice", &change, &signed(&identity, &change)).await.unwrap();
        assert!(paired(&db, "alice", &key).await);
        assert!(keys.read().unwrap().contains(&VerifyingKey::from_bytes(&key).unwrap()), "an admit taken did not admit the key");
    }

    /// Through the whole acceptance: a tenant whose key log rotates onto a key of small
    /// order (a cooperative rotation onto it, signed by the inception's key) has a log that
    /// does not resolve, since that rotation is invalid, so an admit under that key is
    /// refused and nothing is paired.
    #[tokio::test]
    async fn an_admit_under_a_small_order_key_is_refused() {
        use ed25519_dalek::Signer as _;
        use kotton_crypto::ed25519::refused;
        use kotton_wire::kel::{Authorization, EventKind, KelEvent, KeyState};

        let base = tempfile::tempdir().unwrap();
        let inception_key = ed25519_dalek::SigningKey::from_bytes(&[1; 32]);
        let inception = kotton_crypto::kel_verify::build_fresh_inception(&inception_key);
        let mut rotation = KelEvent {
            aid: inception.aid.clone(),
            seq: 1,
            prev_event_digest: Some(kotton_crypto::kel_verify::digest(&inception)),
            kind: EventKind::RotationCooperative,
            key_state: KeyState { group_key: refused::SMALL_ORDER_KEY, threshold: 1, participants: 1 },
            recovery_commitment: inception.recovery_commitment,
            recovery_set: Vec::new(),
            authorization: Authorization::Quorum { sig: vec![0u8; 64] },
            contest_window: None,
        };
        let sig = inception_key.sign(rotation.canonical().as_bytes()).to_bytes().to_vec();
        rotation.authorization = Authorization::Quorum { sig };
        let chain = [inception, rotation];
        let why = resolve_current_key(&chain, &LocalArbiter, false).unwrap_err();
        assert!(why.contains("invalid event at seq 1"), "{why}");
        kotton_identity::kel_store::save_chain(base.path(), "alice", &chain).expect("the key log");

        let db = a_vault_db().await;
        let keys = Arc::new(RwLock::new(HashSet::new()));
        let (key, did) = a_device(2);
        let change = TenantDeviceChange { act: TenantDeviceAct::Admit, device_did: did, public_key: key, said_at_ms: 1 };
        let why = accept(base.path(), &db, &keys, "alice", &change, &refused::under_small_order_key_bytes())
            .await
            .unwrap_err();
        assert!(why.contains("does not resolve to a key"), "{why}");
        assert!(!paired(&db, "alice", &key).await);
        assert!(!keys.read().unwrap().contains(&VerifyingKey::from_bytes(&key).unwrap()));
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
        assert!(!keys.read().unwrap().contains(&VerifyingKey::from_bytes(&key).unwrap()));
    }

    /// **Condition 2 holds the key to the Ed25519 rule**: an admit the identity
    /// signed, of each key vector the rule refuses under a DID naming those bytes,
    /// is refused with the refusal a DID that names another key gets, byte for byte
    /// in the reply, and writes no row.
    #[tokio::test]
    async fn an_admit_of_a_key_the_rule_refuses_is_refused_as_a_did_that_names_no_key() {
        use kotton_crypto::ed25519::refused;
        let base = tempfile::tempdir().unwrap();
        let identity = ed25519_dalek::SigningKey::from_bytes(&[1; 32]);
        a_tenant_at(base.path(), &identity);
        let db = a_vault_db().await;
        let keys = Arc::new(RwLock::new(HashSet::new()));

        let (key, _) = a_device(2);
        let (_, another_did) = a_device(4);
        let misnamed = TenantDeviceChange { act: TenantDeviceAct::Admit, device_did: another_did, public_key: key, said_at_ms: 1 };
        let existing = accept(base.path(), &db, &keys, "alice", &misnamed, &signed(&identity, &misnamed)).await.unwrap_err();
        let existing_reply = serde_json::to_vec(&super::refused(&existing)).unwrap();

        let vectors: Vec<[u8; 32]> = refused::SMALL_ORDER_KEYS
            .into_iter()
            .chain(refused::IDENTITY_OTHER_ENCODINGS)
            .chain([refused::mixed_order_key(), refused::NON_CANONICAL_KEY, refused::NOT_A_POINT])
            .collect();
        assert_eq!(vectors.len(), 14, "one admit per refused key vector");
        for (i, bytes) in vectors.into_iter().enumerate() {
            let did = DidKeyMethod::spelled_over(&bytes).to_string();
            let change = TenantDeviceChange { act: TenantDeviceAct::Admit, device_did: did, public_key: bytes, said_at_ms: 2 + i as u64 };
            let why = accept(base.path(), &db, &keys, "alice", &change, &signed(&identity, &change)).await.unwrap_err();
            assert_eq!(serde_json::to_vec(&super::refused(&why)).unwrap(), existing_reply, "refused key vector {i}: {why}");
            assert!(!paired(&db, "alice", &bytes).await, "a row was written for refused key vector {i}");
            let changes: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM tenant_device_changes WHERE public_key = ?")
                .bind(bytes.as_slice())
                .fetch_one(db.as_ref())
                .await
                .unwrap();
            assert_eq!(changes, 0, "a change was taken for refused key vector {i}");
        }
        assert!(keys.read().unwrap().is_empty());
    }

    /// A tenant whose membership set this vault cannot read, as a vault's is:
    /// its tenant set is its rows, and nothing else.
    struct Sealed;

    #[async_trait::async_trait]
    impl kotton_peer::membership::MemberStore for Sealed {
        async fn member_write(&self, _: &str, _: &[u8]) -> anyhow::Result<()> {
            anyhow::bail!("sealed")
        }
        async fn member_read(&self, _: &str) -> anyhow::Result<Vec<u8>> {
            anyhow::bail!("sealed")
        }
        async fn member_delete(&self, _: &str) -> anyhow::Result<()> {
            anyhow::bail!("sealed")
        }
        async fn member_list(&self, _: &str) -> anyhow::Result<Vec<String>> {
            Ok(Vec::new())
        }
    }

    /// **The vault's tenant set reads a row an earlier build stored under bytes
    /// the rule refuses as no key, and a withdrawal removes it by what is
    /// stored.** One row per key vector the rule refuses sits beside an honest
    /// device the identity admitted. The allowlist rebuilt from the tenant's
    /// rows holds the honest key alone. A withdrawal the identity signed, under
    /// a DID that names no key and is not the one stored with those bytes,
    /// removes nothing; under the DID as stored it removes that row and no
    /// other, and records no change under bytes that are no key. The rebuilt
    /// allowlist is the honest key throughout.
    #[tokio::test]
    async fn a_row_under_bytes_the_rule_refuses_is_read_as_no_key_and_withdrawn_as_stored() {
        let base = tempfile::tempdir().unwrap();
        let identity = ed25519_dalek::SigningKey::from_bytes(&[1; 32]);
        a_tenant_at(base.path(), &identity);
        let db = a_vault_db().await;
        let keys = Arc::new(RwLock::new(HashSet::new()));
        let (honest, honest_did) = a_device(2);
        let admit = TenantDeviceChange { act: TenantDeviceAct::Admit, device_did: honest_did, public_key: honest, said_at_ms: 1 };
        accept(base.path(), &db, &keys, "alice", &admit, &signed(&identity, &admit)).await.unwrap();
        let honest_key = VerifyingKey::from_bytes(&honest).unwrap();

        let refused = kotton_crypto::ed25519::refused_keys();
        for (i, (_, bytes)) in refused.iter().enumerate() {
            let did = DidKeyMethod::spelled_over(bytes).to_string();
            kotton_peer::daemon::db::insert_paired_node(&db, &format!("old-{i}"), "alice", &did, bytes, "[]", 0, Some("full"))
                .await
                .unwrap();
        }
        let tenants: Vec<(String, Arc<dyn kotton_peer::membership::MemberStore>)> = vec![("alice".into(), Arc::new(Sealed))];
        kotton_peer::daemon::nodes::reproject_allowlist(&tenants, &db, &keys).await;
        assert_eq!(*keys.read().unwrap(), HashSet::from([honest_key]), "the tenant set admitted a row that names no key");

        for (i, (name, bytes)) in refused.iter().enumerate() {
            let did = DidKeyMethod::spelled_over(bytes).to_string();
            let elsewhere = format!("did:key:zNotStored{i}");
            let misnamed = TenantDeviceChange { act: TenantDeviceAct::Withdraw, device_did: elsewhere, public_key: *bytes, said_at_ms: 10 + i as u64 };
            let why = accept(base.path(), &db, &keys, "alice", &misnamed, &signed(&identity, &misnamed)).await.unwrap_err();
            assert!(why.contains("names no key, and no row of the tenant's is stored under it"), "{name}: {why}");
            assert!(paired(&db, "alice", bytes).await, "{name}: a withdrawal not as stored removed the row");

            let withdraw = TenantDeviceChange { act: TenantDeviceAct::Withdraw, device_did: did, public_key: *bytes, said_at_ms: 10 + i as u64 };
            accept(base.path(), &db, &keys, "alice", &withdraw, &signed(&identity, &withdraw))
                .await
                .unwrap_or_else(|why| panic!("{name}: the withdrawal as stored was refused: {why}"));
            assert!(!paired(&db, "alice", bytes).await, "{name}: the row stayed");
            assert!(paired(&db, "alice", &honest).await, "{name}: the honest row went with it");
            let changes: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM tenant_device_changes WHERE public_key = ?")
                .bind(bytes.as_slice())
                .fetch_one(db.as_ref())
                .await
                .unwrap();
            assert_eq!(changes, 0, "{name}: a change was recorded under bytes that are no key");
            kotton_peer::daemon::nodes::reproject_allowlist(&tenants, &db, &keys).await;
            assert_eq!(*keys.read().unwrap(), HashSet::from([honest_key]), "{name}");
        }
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

    /// A file-backed pool as the vault's own: WAL, several connections, and
    /// a short busy timeout so a held write lock shows as a timed-out write.
    async fn a_file_pool(dir: &std::path::Path) -> (Arc<SqlitePool>, std::time::Duration) {
        use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions};
        let busy = std::time::Duration::from_millis(1500);
        let opts = SqliteConnectOptions::new()
            .filename(dir.join("agent.db"))
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal)
            .busy_timeout(busy);
        let db = Arc::new(SqlitePoolOptions::new().max_connections(4).connect_with(opts).await.unwrap());
        kotton_device::db::MIGRATOR.run(db.as_ref()).await.expect("migrations");
        init(&db).await.expect("tenant_device_changes");
        (db, busy)
    }

    /// Two writes through the pool, each on its own connection and each
    /// inside the busy timeout, then read back committed from outside it. A
    /// connection the pool was handed back inside a transaction fails this:
    /// either it is one of the two and its write never commits, or it holds
    /// the lock and the other's write times out.
    async fn the_pool_writes(dir: &std::path::Path, db: &Arc<SqlitePool>, busy: std::time::Duration, tag: u8) {
        use sqlx::Connection as _;
        let mut first = db.acquire().await.unwrap();
        let mut second = db.acquire().await.unwrap();
        for (i, conn) in [&mut first, &mut second].into_iter().enumerate() {
            let write = sqlx::query("INSERT INTO tenant_device_changes (user_id, public_key, said_at) VALUES ('bob', ?, 1)")
                .bind(vec![tag, i as u8])
                .execute(&mut **conn);
            tokio::time::timeout(busy, write)
                .await
                .unwrap_or_else(|_| panic!("a write through the pool waited out the busy timeout"))
                .unwrap_or_else(|e| panic!("a write through the pool failed: {e}"));
        }
        drop((first, second));
        let mut outside = sqlx::SqliteConnection::connect_with(
            &sqlx::sqlite::SqliteConnectOptions::new().filename(dir.join("agent.db")),
        )
        .await
        .unwrap();
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM tenant_device_changes WHERE user_id = 'bob' AND hex(public_key) LIKE ?")
            .bind(format!("{tag:02X}%"))
            .fetch_one(&mut outside)
            .await
            .unwrap();
        assert_eq!(n, 2, "a write through the pool did not commit");
    }

    /// **An end statement that fails returns no locked connection to the
    /// pool.** The change is not taken; an unrelated write through the pool
    /// then completes inside the busy timeout; and the next change, for
    /// another key, is taken.
    #[tokio::test]
    async fn a_failed_end_leaves_the_pool_writable() {
        let dir = tempfile::tempdir().unwrap();
        let (db, busy) = a_file_pool(dir.path()).await;
        let keys = Arc::new(RwLock::new(HashSet::new()));
        let (key, _) = a_device(8);
        let change = a_change(TenantDeviceAct::Admit, key, 1);
        let taken = Taken::Admit { key: VerifyingKey::from_bytes(&key).unwrap(), device_did: &change.device_did, said_at_ms: 1 };
        let failed = apply_ending(&db, &keys, "alice", taken, Some("COMMIT TO NOWHERE")).await;
        assert!(failed.is_err(), "an end that failed was reported taken: {failed:?}");
        assert!(!paired(&db, "alice", &key).await, "a change whose end failed was kept");

        the_pool_writes(dir.path(), &db, busy, 1).await;
        let (other, _) = a_device(9);
        tokio::time::timeout(busy, apply_change(&db, &keys, "alice", &a_change(TenantDeviceAct::Admit, other, 2)))
            .await
            .expect("the next change waited out the busy timeout")
            .unwrap()
            .unwrap();
        assert!(paired(&db, "alice", &other).await);
    }

    /// **A transaction dropped before it ends — a cancelled request — returns
    /// no locked connection to the pool**, and what it wrote is not kept.
    #[tokio::test]
    async fn a_transaction_dropped_unended_leaves_the_pool_writable() {
        let dir = tempfile::tempdir().unwrap();
        let (db, busy) = a_file_pool(dir.path()).await;
        let mut tx = Immediate::begin(&db).await.unwrap();
        sqlx::query("INSERT INTO tenant_device_changes (user_id, public_key, said_at) VALUES ('carol', x'00', 1)")
            .execute(tx.conn())
            .await
            .unwrap();
        drop(tx);
        the_pool_writes(dir.path(), &db, busy, 2).await;
        let kept: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM tenant_device_changes WHERE user_id = 'carol'")
            .fetch_one(db.as_ref())
            .await
            .unwrap();
        assert_eq!(kept, 0, "a dropped transaction's write was kept");
    }
}
