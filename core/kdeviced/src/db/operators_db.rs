// SPDX-License-Identifier: AGPL-3.0-or-later
//! The device's operators, for `kdeviced`, in `device.db`
//! (`TASK-a-device-has-operators-not-an-operator`).
//!
//! **A set of keys, each answering for one person.** A row is a credential —
//! the `did:key` a caller proves by signing this connection's nonce — and the
//! account on this device it answers for. The key is the primary key, so no
//! key is ever two people's; a person may hold several. What an operator may do
//! is decided by their key's row, read again on every request
//! (`system::handle_sys_request`), so removing a row ends that key's standing
//! on a connection it already holds.
//!
//! **The last is never removed.** [`remove`] is one statement whose guard is in
//! its own `WHERE`, so two operators stepping each other down at once cannot
//! both succeed and leave the device with nobody: a device always has one, and
//! handing it on is add-then-step-down.
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
    /// It would leave the device with no operator.
    Last(String),
    /// No key of `person`'s own has been kept here yet.
    NoKeyKept(String),
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
            Refusal::Last(who) => write!(
                f,
                "{who} is this device's last operator, and the last is never removed — add another operator first"
            ),
            Refusal::NoKeyKept(p) => write!(
                f,
                "{p} holds no key of their own on this device yet — their Kotton makes one the next time they unlock here"
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

/// Step down `who` — one key, or a person, which takes every key of theirs.
/// Refused when nothing matches, or when it would leave no operator. The guard
/// is in the one `DELETE`'s own `WHERE`, so it holds against a concurrent
/// removal: whichever runs second finds itself the last. Returns the keys it
/// removed.
pub async fn remove(pool: &SqlitePool, who: &str) -> io::Result<Result<Vec<String>, Refusal>> {
    let matching: Vec<String> = sqlx::query("SELECT did FROM operators WHERE did = ?1 OR person = ?1")
        .bind(who)
        .fetch_all(pool)
        .await
        .map_err(db_err("remove"))?
        .into_iter()
        .map(|r| r.get::<String, _>("did"))
        .collect();
    if matching.is_empty() {
        return Ok(Err(Refusal::NotAnOperator(who.to_string())));
    }
    let done = sqlx::query(
        "DELETE FROM operators WHERE (did = ?1 OR person = ?1) \
         AND EXISTS (SELECT 1 FROM operators WHERE did <> ?1 AND COALESCE(person, '') <> ?1)",
    )
    .bind(who)
    .execute(pool)
    .await
    .map_err(db_err("remove"))?;
    if done.rows_affected() == 0 {
        return Ok(Err(Refusal::Last(who.to_string())));
    }
    Ok(Ok(matching))
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
