// SPDX-License-Identifier: AGPL-3.0-or-later
//! The device's operators, for `kdeviced`, in `device.db`
//! (`TASK-a-device-has-operators-not-an-operator`).
//!
//! **A set of keys, each answering for one person.** A row is a credential —
//! the `did:key` a caller proves by signing the login message over this
//! connection's challenge (`kotton_wire::sys_ipc::login_message`) — and the
//! account on this device it answers for. The key is the primary key, so no
//! key is ever two people's; a person may hold several. What an operator may do
//! is decided by their key's row, read again on every request
//! (`system::handle_sys_request`), so removing a row ends that key's standing
//! on a connection it already holds.
//!
//! **The last is never removed.** The operator a device always keeps is a row
//! that names a key: one somebody can sign for. A row under a string that is
//! not the `did:key` of an Ed25519 key is no operator and does not stand in for
//! one (kottonllc/kotton#597); nothing is admitted under it at login, and
//! [`remove`] removes it by the DID as stored. [`remove`] reads the set once
//! and then removes exactly the rows it read in one statement whose guard is in
//! its own `WHERE`, so two operators stepping each other down at once cannot
//! both succeed and leave the device with nobody, and a key given to a person
//! while they are being stepped down is not taken with them: a device always
//! has one, and handing it on is add-then-step-down.
//!
//! **First run.** When the set is empty, the first caller to prove a key is
//! enrolled ([`bootstrap`]) — trust on first use, DEC-0017 — in one statement
//! that inserts only into an empty table, so two first callers racing enrol one.
//! That row answers for nobody until an operator binds it to a person
//! ([`add`], naming the same key).
//!
//! **Every act is kept under its key** ([`record_act`]), so nothing an operator
//! does is anonymous among them.

use kotton_wire::DeviceOperator;
use sqlx::{Row as _, SqlitePool};
use std::io;

/// Open (or create) `device.db` and run any pending migrations.
///
/// Parent directories are created if they don't exist, owner-only
/// (`kotton_common::fs::create_dir_all_owner_only`): this is one of the
/// components that may make a node's base dir and `system/` first.
pub async fn open(db_path: &std::path::Path) -> io::Result<SqlitePool> {
    if let Some(parent) = db_path.parent() {
        kotton_common::fs::create_dir_all_owner_only(parent)
            .map_err(|e| io::Error::other(format!("cannot create device db dir: {e}")))?;
    }

    let url = format!("sqlite://{}?mode=rwc", db_path.display());
    let pool = SqlitePool::connect(&url)
        .await
        .map_err(|e| io::Error::other(format!("cannot open device.db: {e}")))?;

    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .map_err(|e| io::Error::other(format!("device.db migration failed: {e}")))?;

    Ok(pool)
}

fn db_err(what: &str) -> impl Fn(sqlx::Error) -> io::Error + '_ {
    move |e| io::Error::other(format!("{what} failed: {e}"))
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

/// Why an operator change was refused — the sentence the caller reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// `person` has no account on this device.
    NoAccount(String),
    /// The key is already another person's.
    SharedKey { did: String, person: String },
    /// Nothing in the set is that key or that person's.
    NotAnOperator(String),
    /// No key of `person`'s own has been kept here yet.
    NoKeyKept(String),
    /// It would leave the device with no operator row that names a key.
    LastKey(String),
    /// The key kept for `person` names no Ed25519 key, so nobody can sign for it.
    KeptNamesNoKey { person: String, did: String },
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Refusal::NoAccount(p) => write!(
                f,
                "{p} has no account on this device — an operator is one of the people who use it"
            ),
            Refusal::SharedKey { did, person } => write!(
                f,
                "{did} is already {person}'s key — each operator holds their own, and a key is never shared"
            ),
            Refusal::NotAnOperator(who) => write!(f, "{who} is not one of this device's operators"),
            Refusal::NoKeyKept(p) => write!(
                f,
                "{p} holds no key of their own on this device yet — their Kotton makes one the next time they unlock here"
            ),
            Refusal::LastKey(who) => write!(
                f,
                "{who} holds this device's last operator key that names an Ed25519 key, and the last is never removed — \
                 a row that names no key is no operator anyone can sign as, so it does not stand in for one; add another operator first"
            ),
            Refusal::KeptNamesNoKey { person, did } => write!(
                f,
                "the key kept for {person}, {did}, is not the did:key of an Ed25519 key, so nobody can sign for it and \
                 it is not made an operator — remove it by that DID as stored"
            ),
        }
    }
}

/// Whether `did` is one of this device's operator keys.
pub async fn is_operator(pool: &SqlitePool, did: &str) -> io::Result<bool> {
    let row = sqlx::query("SELECT 1 FROM operators WHERE did = ?")
        .bind(did)
        .fetch_optional(pool)
        .await
        .map_err(db_err("operator lookup"))?;
    Ok(row.is_some())
}

/// Enrol `did` as the first operator if, and only if, the set is empty — one
/// statement, so two first callers cannot both be enrolled. Returns whether it
/// was. `person`, when given, is who the key answers for from its first
/// instant (a person's own daemon naming them); the caller has checked it is an
/// account. Bound in the same statement, so no reader ever sees the first key
/// answering for nobody between its enrolment and its binding.
pub async fn bootstrap(pool: &SqlitePool, did: &str, person: Option<&str>) -> io::Result<bool> {
    let done = sqlx::query(
        "INSERT INTO operators (did, person, added_at, added_by) \
         SELECT ?, ?, ?, 'bootstrap' WHERE NOT EXISTS (SELECT 1 FROM operators)",
    )
    .bind(did)
    .bind(person)
    .bind(now())
    .execute(pool)
    .await
    .map_err(db_err("bootstrap"))?;
    Ok(done.rows_affected() == 1)
}

/// Make `person` an operator holding `did`, added by the key `added_by`.
/// `accounts` are the people with an account on this device; `person` must be
/// one. A key already `person`'s is left as it is; the first-run key, which
/// answers for nobody, is bound to `person`; a key that is someone else's is
/// refused.
pub async fn add(
    pool: &SqlitePool,
    did: &str,
    person: &str,
    added_by: &str,
    accounts: &[String],
) -> io::Result<Result<(), Refusal>> {
    if !accounts.iter().any(|a| a == person) {
        return Ok(Err(Refusal::NoAccount(person.to_string())));
    }
    let mut tx = pool.begin().await.map_err(db_err("add"))?;
    let existing: Option<Option<String>> = sqlx::query("SELECT person FROM operators WHERE did = ?")
        .bind(did)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db_err("add"))?
        .map(|r| r.get::<Option<String>, _>("person"));
    match existing {
        Some(Some(p)) if p == person => {}
        Some(Some(p)) => {
            return Ok(Err(Refusal::SharedKey {
                did: did.to_string(),
                person: p,
            }))
        }
        Some(None) => {
            sqlx::query("UPDATE operators SET person = ? WHERE did = ? AND person IS NULL")
                .bind(person)
                .bind(did)
                .execute(&mut *tx)
                .await
                .map_err(db_err("add"))?;
        }
        None => {
            sqlx::query("INSERT INTO operators (did, person, added_at, added_by) VALUES (?, ?, ?, ?)")
                .bind(did)
                .bind(person)
                .bind(now())
                .bind(added_by)
                .execute(&mut *tx)
                .await
                .map_err(db_err("add"))?;
        }
    }
    tx.commit().await.map_err(db_err("add"))?;
    Ok(Ok(()))
}

/// Whether `did` is the `did:key` of an Ed25519 key: a row under it is one
/// somebody can sign for. A row under any other string, bytes the rule refuses
/// or another spelling of a key's `did:key`, is no operator anyone can sign as
/// (kottonllc/kotton#597), as migration 0004 says of the rows it leaves behind.
pub fn names_a_key(did: &str) -> bool {
    did.parse::<kotton_wire::did::Did>()
        .ok()
        .is_some_and(|d| kotton_crypto::DidKeyMethod::to_public_key(&d).is_ok())
}

/// Step down `who` — one key, or a person, which takes every key of theirs —
/// and remove a kept key stored under `who` as a DID. Refused when nothing
/// matches, or when it would leave no operator row that names a key: a row
/// nobody can sign for is not an operator and does not stand in for one.
/// Returns the keys it removed. A kept key is matched by its DID as stored,
/// never by person, and its removal leaves no device without an operator.
pub async fn remove(pool: &SqlitePool, who: &str) -> io::Result<Result<Vec<String>, Refusal>> {
    remove_with(pool, who, || async {}).await
}

/// [`remove`], with `between` run after the set is read and before the one
/// `DELETE`. A test runs another writer there, to hold that what is removed is
/// what was read, and that the guard is the `DELETE`'s own.
///
/// **One read, one statement.** The set is read once: the rows `who` names,
/// and the other rows that name a key. Whether a DID names a key is a fact of
/// the string alone, so it is decided from that read. The `DELETE` then names
/// exactly the DIDs read, never `who` again, so a row written after the read
/// (a key the same person is given meanwhile) is not removed by it. Where the
/// rows read include one that names a key, the guard is in the same
/// statement's `WHERE`: another row that names a key, of those read, must
/// still be there as it runs. So of two removals at once, whichever runs
/// second finds itself the last, and a row added meanwhile is never counted
/// on before it was read. There is no second guard.
async fn remove_with<F: std::future::Future<Output = ()>>(
    pool: &SqlitePool,
    who: &str,
    between: impl FnOnce() -> F,
) -> io::Result<Result<Vec<String>, Refusal>> {
    let rows: Vec<(String, Option<String>)> = sqlx::query("SELECT did, person FROM operators")
        .fetch_all(pool)
        .await
        .map_err(db_err("remove"))?
        .into_iter()
        .map(|r| (r.get::<String, _>("did"), r.get::<Option<String>, _>("person")))
        .collect();
    let (matching, others): (Vec<_>, Vec<_>) =
        rows.into_iter().partition(|(did, person)| did == who || person.as_deref() == Some(who));
    let matching: Vec<String> = matching.into_iter().map(|(did, _)| did).collect();
    let others: Vec<String> = others.into_iter().map(|(did, _)| did).filter(|d| names_a_key(d)).collect();
    let kept = sqlx::query("SELECT 1 FROM operator_keys_kept WHERE did = ?")
        .bind(who)
        .fetch_optional(pool)
        .await
        .map_err(db_err("remove"))?
        .is_some();
    if matching.is_empty() && !kept {
        return Ok(Err(Refusal::NotAnOperator(who.to_string())));
    }
    between().await;
    if !matching.is_empty() {
        let removes_a_key = matching.iter().any(|d| names_a_key(d));
        let marks = |from: usize, n: usize| (from..from + n).map(|i| format!("?{i}")).collect::<Vec<_>>().join(", ");
        let sql = format!(
            "DELETE FROM operators WHERE did IN ({}) AND (?1 = 0 OR EXISTS (SELECT 1 FROM operators WHERE did IN ({})))",
            marks(2, matching.len()),
            marks(2 + matching.len(), others.len()),
        );
        let mut q = sqlx::query(&sql).bind(removes_a_key);
        for d in matching.iter().chain(&others) {
            q = q.bind(d);
        }
        let done = q.execute(pool).await.map_err(db_err("remove"))?;
        if removes_a_key && done.rows_affected() == 0 {
            return Ok(Err(Refusal::LastKey(who.to_string())));
        }
    }
    let mut removed = matching;
    if kept {
        sqlx::query("DELETE FROM operator_keys_kept WHERE did = ?")
            .bind(who)
            .execute(pool)
            .await
            .map_err(db_err("remove"))?;
        if !removed.iter().any(|d| d == who) {
            removed.push(who.to_string());
        }
    }
    Ok(Ok(removed))
}

/// What keeping a person's own key came to ([`keep_own_key`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Kept {
    /// Kept as `person`'s — or it already was.
    Kept,
    /// `person` has no account on this device.
    NoAccount,
    /// A different key was kept for `person` first, and it stands.
    AnotherKey,
    /// The key is kept for someone else.
    Taken,
    /// The key is an operator's — enrolled a moment ago by a proof of the same
    /// key on another connection. It stands; nothing is kept.
    Operator,
}

/// Keep `did` as `person`'s own key: proven by its holder, standing for
/// nothing until an operator makes `person` an operator ([`take_kept_key`]).
/// The first key kept for a person is theirs; a second is refused.
pub async fn keep_own_key(
    pool: &SqlitePool,
    did: &str,
    person: &str,
    accounts: &[String],
) -> io::Result<Kept> {
    if !accounts.iter().any(|a| a == person) {
        return Ok(Kept::NoAccount);
    }
    if is_operator(pool, did).await? {
        return Ok(Kept::Operator);
    }
    // One statement decides it, so two proofs of the same key at once — a
    // person's daemon keeping it at unlock while their pane reads — both find
    // it kept rather than one of them failing on the constraint; and two
    // different keys for one person at once keep exactly the first.
    sqlx::query("INSERT OR IGNORE INTO operator_keys_kept (did, person, kept_at) VALUES (?, ?, ?)")
        .bind(did)
        .bind(person)
        .bind(now())
        .execute(pool)
        .await
        .map_err(db_err("keep"))?;
    let held: Vec<(String, String)> = sqlx::query("SELECT did, person FROM operator_keys_kept WHERE did = ? OR person = ?")
        .bind(did)
        .bind(person)
        .fetch_all(pool)
        .await
        .map_err(db_err("keep"))?
        .into_iter()
        .map(|r| (r.get("did"), r.get("person")))
        .collect();
    Ok(if held.iter().any(|(d, p)| d == did && p == person) {
        Kept::Kept
    } else if held.iter().any(|(d, _)| d == did) {
        Kept::Taken
    } else {
        Kept::AnotherKey
    })
}

/// The key kept as `person`'s own, if any.
pub async fn kept_key(pool: &SqlitePool, person: &str) -> io::Result<Option<String>> {
    Ok(sqlx::query("SELECT did FROM operator_keys_kept WHERE person = ?")
        .bind(person)
        .fetch_optional(pool)
        .await
        .map_err(db_err("kept key"))?
        .map(|r| r.get("did")))
}

/// Make `person` an operator holding the key kept as theirs, added by the key
/// `added_by`: the one way an operator makes someone else an operator without
/// naming a key. Refused as [`add`] refuses, and when nothing is kept for them.
pub async fn take_kept_key(
    pool: &SqlitePool,
    person: &str,
    added_by: &str,
    accounts: &[String],
) -> io::Result<Result<String, Refusal>> {
    if !accounts.iter().any(|a| a == person) {
        return Ok(Err(Refusal::NoAccount(person.to_string())));
    }
    let Some(did) = kept_key(pool, person).await? else {
        return Ok(Err(Refusal::NoKeyKept(person.to_string())));
    };
    // Every writer of a row that holds a key constructs the key first: a kept
    // row that names none is not moved into the operators.
    if !names_a_key(&did) {
        return Ok(Err(Refusal::KeptNamesNoKey { person: person.to_string(), did }));
    }
    if let Err(refused) = add(pool, &did, person, added_by, accounts).await? {
        return Ok(Err(refused));
    }
    sqlx::query("DELETE FROM operator_keys_kept WHERE did = ?")
        .bind(&did)
        .execute(pool)
        .await
        .map_err(db_err("take kept key"))?;
    Ok(Ok(did))
}

/// Bind each first-run or carried-over row whose key is itself an account's
/// DID to that account — the key a person's own identity holds answers for
/// them. Run when `kdeviced` opens the file.
pub async fn bind_own_keys(pool: &SqlitePool, accounts: &[String]) -> io::Result<()> {
    for account in accounts {
        sqlx::query("UPDATE operators SET person = ?1 WHERE did = ?1 AND person IS NULL")
            .bind(account)
            .execute(pool)
            .await
            .map_err(db_err("bind"))?;
    }
    Ok(())
}

/// Every operator, oldest first.
pub async fn list(pool: &SqlitePool) -> io::Result<Vec<DeviceOperator>> {
    let rows = sqlx::query("SELECT did, person, added_at, added_by FROM operators ORDER BY added_at ASC, did ASC")
        .fetch_all(pool)
        .await
        .map_err(db_err("list operators"))?;
    Ok(rows
        .into_iter()
        .map(|r| DeviceOperator {
            did: r.get("did"),
            person: r.get("person"),
            added_at: r.get("added_at"),
            added_by: r.get("added_by"),
        })
        .collect())
}

/// A note for each `operators` row, and each kept key, whose DID names no key
/// ([`names_a_key`]), by the DID as stored, which is what `sudoers remove`
/// takes (kottonllc/kotton#605). Operators first, oldest first; a DID in both
/// tables is noted once.
pub async fn notes(pool: &SqlitePool) -> io::Result<Vec<kotton_wire::note::RowNote>> {
    let dids: Vec<String> = sqlx::query(
        "SELECT did FROM (SELECT did, 0 AS t, added_at AS at FROM operators \
         UNION ALL SELECT did, 1 AS t, kept_at AS at FROM operator_keys_kept) ORDER BY t, at, did",
    )
    .fetch_all(pool)
    .await
    .map_err(db_err("list operators"))?
    .into_iter()
    .map(|r| r.get::<String, _>("did"))
    .collect();
    let mut notes: Vec<kotton_wire::note::RowNote> = Vec::new();
    for did in dids.into_iter().filter(|d| !names_a_key(d)) {
        if !notes.iter().any(|n| n.name == did) {
            notes.push(kotton_wire::note::RowNote::names_no_key(did));
        }
    }
    Ok(notes)
}

/// The line `kdeviced` logs at start when it holds operator rows and none of
/// them names a key: nobody can sign in as an operator, so no listing can be
/// reached to say so. `None` with no rows (a first run) or with one that names
/// a key. The way back is the file, with the daemon stopped (`open`).
pub async fn none_names_a_key(pool: &SqlitePool) -> io::Result<Option<String>> {
    let dids: Vec<String> = sqlx::query("SELECT did FROM operators")
        .fetch_all(pool)
        .await
        .map_err(db_err("list operators"))?
        .into_iter()
        .map(|r| r.get::<String, _>("did"))
        .collect();
    if dids.is_empty() || dids.iter().any(|d| names_a_key(d)) {
        return Ok(None);
    }
    Ok(Some(format!(
        "no operator row of this device names an Ed25519 key ({} row{} that nobody can sign as), so nobody can sign \
         in as its operator; with kdeviced stopped, removing system/device.db makes the next start a first run, \
         which keeps accounts and their data",
        dids.len(),
        if dids.len() == 1 { "" } else { "s" }
    )))
}

/// Whether `person` holds any operator key here.
pub async fn is_operator_person(pool: &SqlitePool, person: &str) -> io::Result<bool> {
    let row = sqlx::query("SELECT 1 FROM operators WHERE person = ? LIMIT 1")
        .bind(person)
        .fetch_optional(pool)
        .await
        .map_err(db_err("operator lookup"))?;
    Ok(row.is_some())
}

/// One act an operator took, as the device kept it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperatorAct {
    /// The key that authenticated the connection the act was said on.
    pub did: String,
    /// The request's variant name.
    pub act: String,
    /// What it named — a user, a key, a name — or empty.
    pub subject: String,
    /// Whether it was carried out.
    pub ok: bool,
    pub at: i64,
}

/// Keep one act under the key that took it.
pub async fn record_act(pool: &SqlitePool, did: &str, act: &str, subject: &str, ok: bool) -> io::Result<()> {
    sqlx::query("INSERT INTO operator_acts (did, act, subject, ok, at) VALUES (?, ?, ?, ?, ?)")
        .bind(did)
        .bind(act)
        .bind(subject)
        .bind(ok)
        .bind(now())
        .execute(pool)
        .await
        .map_err(db_err("record act"))?;
    Ok(())
}

/// Every act kept, oldest first.
pub async fn acts(pool: &SqlitePool) -> io::Result<Vec<OperatorAct>> {
    let rows = sqlx::query("SELECT did, act, subject, ok, at FROM operator_acts ORDER BY id")
        .fetch_all(pool)
        .await
        .map_err(db_err("read acts"))?;
    Ok(rows
        .into_iter()
        .map(|r| OperatorAct {
            did: r.get("did"),
            act: r.get("act"),
            subject: r.get("subject"),
            ok: r.get::<bool, _>("ok"),
            at: r.get("at"),
        })
        .collect())
}

/// Append a row to the supervisor's own lifecycle log (RFC-0063 events
/// split). Best-effort by design: a full disk must not stop a spawn.
pub async fn log_device_event(pool: &SqlitePool, category: &str, message: &str, payload: Option<&str>) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let id = uuid::Uuid::new_v4().to_string();
    if let Err(e) = sqlx::query(
        "INSERT INTO device_events (id, category, message, payload, timestamp) \
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(category)
    .bind(message)
    .bind(payload)
    .bind(now)
    .execute(pool)
    .await
    {
        tracing::warn!(error = %e, "device event log write failed");
    }
}

/// Read the human-readable device name, if set.
pub async fn get_device_name(pool: &SqlitePool) -> io::Result<Option<String>> {
    let row: Option<(String,)> =
        sqlx::query_as("SELECT value FROM device_settings WHERE key = 'device_name'")
            .fetch_optional(pool)
            .await
            .map_err(|e| io::Error::other(format!("get_device_name failed: {e}")))?;
    Ok(row.map(|(v,)| v))
}

/// Set (or overwrite) the human-readable device name.
pub async fn set_device_name(pool: &SqlitePool, name: &str) -> io::Result<()> {
    sqlx::query("INSERT OR REPLACE INTO device_settings (key, value) VALUES ('device_name', ?)")
        .bind(name)
        .execute(pool)
        .await
        .map_err(|e| io::Error::other(format!("set_device_name failed: {e}")))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The `did:key` of the key made from `seed`.
    fn did_of(seed: u8) -> String {
        let key = kotton_crypto::ed25519::verifying_key(&ed25519_dalek::SigningKey::from_bytes(&[seed; 32]));
        kotton_crypto::DidKeyMethod::from_public_key(&key).to_string()
    }

    async fn a_device_db() -> (tempfile::TempDir, SqlitePool) {
        let dir = tempfile::tempdir().unwrap();
        let pool = open(&dir.path().join("system").join("device.db")).await.unwrap();
        (dir, pool)
    }

    /// The operator rows that name a key.
    async fn keyed(pool: &SqlitePool) -> Vec<String> {
        list(pool).await.unwrap().into_iter().map(|o| o.did).filter(|d| names_a_key(d)).collect()
    }

    /// **What is removed is what was read.** Ben holds one row that names no key, and Ana is
    /// an operator under hers. While Ben is being stepped down, between the read and the
    /// `DELETE`, Ana makes Ben an operator under his own key. The removal takes the row it
    /// read and not the one written after it: Ben's key is still an operator's afterwards.
    #[tokio::test]
    async fn a_key_given_while_a_person_is_stepped_down_is_not_taken_with_them() {
        let (_dir, pool) = a_device_db().await;
        let (ana, ben, ben_key) = (did_of(1), "ben".to_string(), did_of(2));
        let accounts = vec![ana.clone(), ben.clone()];
        assert!(bootstrap(&pool, &ana, Some(&ana)).await.unwrap());
        let no_key = kotton_crypto::DidKeyMethod::spelled_over(&kotton_crypto::ed25519::refused::NOT_A_POINT).to_string();
        sqlx::query("INSERT INTO operators (did, person, added_at, added_by) VALUES (?, ?, 0, 'an earlier build')")
            .bind(&no_key)
            .bind(&ben)
            .execute(&pool)
            .await
            .unwrap();

        let removed = remove_with(&pool, &ben, || async {
            add(&pool, &ben_key, &ben, &ana, &accounts).await.unwrap().unwrap();
        })
        .await
        .unwrap()
        .unwrap();
        assert_eq!(removed, vec![no_key.clone()], "the removal took a row it did not read");
        assert!(is_operator(&pool, &ben_key).await.unwrap(), "Ben's key, given during the removal, was taken");
        assert!(!is_operator(&pool, &no_key).await.unwrap(), "the row that was read stayed");
    }

    /// **Two removals and an add at once never leave the set without a row that names a
    /// key.** Ana and Ben each step the other's key down while Cai is added, many times.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn two_removals_and_an_add_at_once_leave_a_row_that_names_a_key() {
        for round in 0..40 {
            let (_dir, pool) = a_device_db().await;
            let (ana, ben, cai) = (did_of(1), did_of(2), did_of(3));
            let accounts = vec![ana.clone(), ben.clone(), cai.clone()];
            assert!(bootstrap(&pool, &ana, Some(&ana)).await.unwrap());
            add(&pool, &ben, &ben, &ana, &accounts).await.unwrap().unwrap();
            let no_key = kotton_crypto::DidKeyMethod::spelled_over(&kotton_crypto::ed25519::refused::SMALL_ORDER_KEY).to_string();
            sqlx::query("INSERT INTO operators (did, person, added_at, added_by) VALUES (?, NULL, 0, 'an earlier build')")
                .bind(&no_key)
                .execute(&pool)
                .await
                .unwrap();
            let (a, b, c) = tokio::join!(remove(&pool, &ana), remove(&pool, &ben), add(&pool, &cai, &cai, &ana, &accounts));
            let (a, b) = (a.unwrap(), b.unwrap());
            // `add` begins a deferred transaction, which can meet the lock at once and say so
            // (`database is locked`); the person says it again. The set is what is held here.
            let added = match c {
                Ok(c) => c.is_ok(),
                Err(e) => {
                    assert!(e.to_string().contains("database is locked"), "round {round}: {e}");
                    false
                }
            };
            let left = keyed(&pool).await;
            assert!(!left.is_empty(), "round {round}: no row that names a key is left ({a:?}, {b:?}, added: {added})");
            assert!(a.is_err() || b.is_err() || left.contains(&cai), "round {round}: both removals succeeded with nobody else to stand");
        }
    }
}
