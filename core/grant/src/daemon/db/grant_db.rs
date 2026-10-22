// SPDX-License-Identifier: AGPL-3.0-or-later
//! Grant enforcement DB helpers.
//!
//! Covers three tables added in migration `0010_grant_enforcement.sql`:
//!
//! - `app_grant_envelopes` — signed `GrantEnvelope` JSON blobs bound to an app
//! - `revocation_list`     — envelopes that have been explicitly revoked
//! - `trusted_issuers`     — DIDs whose cross-DID grants are accepted

use kotton_wire::GrantEnvelope;
use kotton_common::time::now_secs;
use sqlx::SqlitePool;
use std::io;

// ── app_grant_envelopes ───────────────────────────────────────────────────────

/// Persist a signed `GrantEnvelope` for `app_id`.
pub async fn store_envelope(
    pool: &SqlitePool,
    app_id: &str,
    envelope: &GrantEnvelope,
) -> io::Result<()> {
    let json = serde_json::to_string(envelope)
        .map_err(|e| io::Error::other(format!("envelope serialize: {e}")))?;
    let now = now_secs();

    sqlx::query(
        "INSERT OR REPLACE INTO app_grant_envelopes (id, app_id, envelope_json, stored_at)
         VALUES (?, ?, ?, ?)",
    )
    .bind(&envelope.id)
    .bind(app_id)
    .bind(&json)
    .bind(now)
    .execute(pool)
    .await
    .map_err(|e| io::Error::other(format!("store_envelope: {e}")))?;

    Ok(())
}

/// Load all stored `GrantEnvelope`s for `app_id`.
pub async fn get_envelopes_for_app(
    pool: &SqlitePool,
    app_id: &str,
) -> io::Result<Vec<GrantEnvelope>> {
    let rows: Vec<(String,)> =
        sqlx::query_as("SELECT envelope_json FROM app_grant_envelopes WHERE app_id = ?")
            .bind(app_id)
            .fetch_all(pool)
            .await
            .map_err(|e| io::Error::other(format!("get_envelopes_for_app: {e}")))?;

    rows.into_iter()
        .map(|(json,)| {
            serde_json::from_str::<GrantEnvelope>(&json)
                .map_err(|e| io::Error::other(format!("envelope deserialize: {e}")))
        })
        .collect()
}

/// Delete one grant envelope by id.
///
/// Used to drop envelopes that predate the signed `app_id` binding, which are
/// re-minted from the recorded approval (`DEC-0052`).
pub async fn delete_envelope(pool: &SqlitePool, envelope_id: &str) -> io::Result<()> {
    sqlx::query("DELETE FROM app_grant_envelopes WHERE id = ?")
        .bind(envelope_id)
        .execute(pool)
        .await
        .map_err(|e| io::Error::other(format!("delete_envelope: {e}")))?;
    Ok(())
}

/// Delete all grant envelopes for `app_id` (called on uninstall).
pub async fn delete_envelopes_for_app(pool: &SqlitePool, app_id: &str) -> io::Result<()> {
    sqlx::query("DELETE FROM app_grant_envelopes WHERE app_id = ?")
        .bind(app_id)
        .execute(pool)
        .await
        .map_err(|e| io::Error::other(format!("delete_envelopes_for_app: {e}")))?;
    Ok(())
}

// ── revocation_list ───────────────────────────────────────────────────────────

/// Return `true` if `envelope_id` is in the revocation list.
pub async fn is_revoked(pool: &SqlitePool, envelope_id: &str) -> io::Result<bool> {
    let row: Option<(String,)> =
        sqlx::query_as("SELECT envelope_id FROM revocation_list WHERE envelope_id = ?")
            .bind(envelope_id)
            .fetch_optional(pool)
            .await
            .map_err(|e| io::Error::other(format!("is_revoked: {e}")))?;
    Ok(row.is_some())
}

/// Add `envelope_id` to the revocation list.
pub async fn revoke_envelope(pool: &SqlitePool, envelope_id: &str) -> io::Result<()> {
    let now = now_secs();
    sqlx::query("INSERT OR IGNORE INTO revocation_list (envelope_id, revoked_at) VALUES (?, ?)")
        .bind(envelope_id)
        .bind(now)
        .execute(pool)
        .await
        .map_err(|e| io::Error::other(format!("revoke_envelope: {e}")))?;
    Ok(())
}

// ── trusted_issuers ───────────────────────────────────────────────────────────

/// Return `true` if `did` is in the trusted-issuer set.
pub async fn is_trusted_issuer(pool: &SqlitePool, did: &str) -> io::Result<bool> {
    let row: Option<(String,)> = sqlx::query_as("SELECT did FROM trusted_issuers WHERE did = ?")
        .bind(did)
        .fetch_optional(pool)
        .await
        .map_err(|e| io::Error::other(format!("is_trusted_issuer: {e}")))?;
    Ok(row.is_some())
}

/// Add `did` to the trusted-issuer set.
pub async fn add_trusted_issuer(pool: &SqlitePool, did: &str) -> io::Result<()> {
    let now = now_secs();
    sqlx::query("INSERT OR IGNORE INTO trusted_issuers (did, added_at) VALUES (?, ?)")
        .bind(did)
        .bind(now)
        .execute(pool)
        .await
        .map_err(|e| io::Error::other(format!("add_trusted_issuer: {e}")))?;
    Ok(())
}

/// Remove `did` from the trusted-issuer set.
pub async fn remove_trusted_issuer(pool: &SqlitePool, did: &str) -> io::Result<()> {
    sqlx::query("DELETE FROM trusted_issuers WHERE did = ?")
        .bind(did)
        .execute(pool)
        .await
        .map_err(|e| io::Error::other(format!("remove_trusted_issuer: {e}")))?;
    Ok(())
}

/// List all trusted-issuer DIDs.
pub async fn list_trusted_issuers(pool: &SqlitePool) -> io::Result<Vec<String>> {
    let rows: Vec<(String,)> = sqlx::query_as("SELECT did FROM trusted_issuers ORDER BY added_at")
        .fetch_all(pool)
        .await
        .map_err(|e| io::Error::other(format!("list_trusted_issuers: {e}")))?;
    Ok(rows.into_iter().map(|(d,)| d).collect())
}

// ── imported_grant_envelopes ──────────────────────────────────────────────────

/// Store a cross-DID `GrantEnvelope` imported via `kotton grant import`.
pub async fn store_imported_envelope(
    pool: &SqlitePool,
    envelope: &GrantEnvelope,
) -> io::Result<()> {
    let json = serde_json::to_string(envelope)
        .map_err(|e| io::Error::other(format!("envelope serialize: {e}")))?;
    let now = now_secs();

    sqlx::query(
        "INSERT OR REPLACE INTO imported_grant_envelopes \
         (id, issuer_did, subject_did, envelope_json, imported_at) \
         VALUES (?, ?, ?, ?, ?)",
    )
    .bind(&envelope.id)
    .bind(envelope.issuer_did.to_string())
    .bind(envelope.subject_did.to_string())
    .bind(&json)
    .bind(now)
    .execute(pool)
    .await
    .map_err(|e| io::Error::other(format!("store_imported_envelope: {e}")))?;

    Ok(())
}

/// Load all imported `GrantEnvelope`s for `subject_did`.
pub async fn get_imported_envelopes(
    pool: &SqlitePool,
    subject_did: &str,
) -> io::Result<Vec<GrantEnvelope>> {
    let rows: Vec<(String,)> =
        sqlx::query_as("SELECT envelope_json FROM imported_grant_envelopes WHERE subject_did = ?")
            .bind(subject_did)
            .fetch_all(pool)
            .await
            .map_err(|e| io::Error::other(format!("get_imported_envelopes: {e}")))?;

    rows.into_iter()
        .map(|(json,)| {
            serde_json::from_str::<GrantEnvelope>(&json)
                .map_err(|e| io::Error::other(format!("envelope deserialize: {e}")))
        })
        .collect()
}

// ── grant_lifetime (TASK-a-grant-cannot-be-once-or-while-open) ─────────────────
//
// The two lifetimes a clock cannot express — `Uses(n)` and `WhileOpen` — keep
// their mutable enforcement state here, beside the signed envelope. Exhaustion
// is written into `revocation_list`, so the runner's existing revocation check
// is the single place a spent grant is denied.

use kotton_wire::GrantLifetime;

/// Record a grant's lifetime, for the two that need daemon-tracked state.
///
/// `UntilRevoked` and `Seconds` are no-ops: their enforcement is the revocation
/// list and `expires_at`, and writing a row for them would only add a way to be
/// wrong. `Uses` stores its counter; `WhileOpen` stores its kind and binds to an
/// instance later, at activation.
pub async fn set_lifetime(
    pool: &SqlitePool,
    app_id: &str,
    envelope_id: &str,
    lifetime: GrantLifetime,
) -> io::Result<()> {
    let (kind, uses) = match lifetime {
        GrantLifetime::Uses(n) => ("uses", Some(n as i64)),
        GrantLifetime::WhileOpen => ("while_open", None),
        GrantLifetime::UntilRevoked | GrantLifetime::Seconds(_) => return Ok(()),
    };
    let now = now_secs();
    sqlx::query(
        "INSERT OR REPLACE INTO grant_lifetime \
         (envelope_id, app_id, kind, uses_remaining, bound_instance, set_at) \
         VALUES (?, ?, ?, ?, NULL, ?)",
    )
    .bind(envelope_id)
    .bind(app_id)
    .bind(kind)
    .bind(uses)
    .bind(now)
    .execute(pool)
    .await
    .map_err(|e| io::Error::other(format!("set_lifetime: {e}")))?;
    Ok(())
}

/// Consume one activation of a `Uses` grant, atomically.
///
/// A single SQL statement decrements only while the counter is above zero, so
/// two activations racing cannot both succeed on a one-use grant — the second
/// affects no rows. Returns `true` when this call consumed an activation (the
/// grant is live for it), `false` when the grant was already spent or is not a
/// `Uses` grant. When it drives the counter to zero it revokes the envelope, so
/// every later check denies it through the one revocation path.
pub async fn consume_use(pool: &SqlitePool, envelope_id: &str) -> io::Result<bool> {
    let res = sqlx::query(
        "UPDATE grant_lifetime SET uses_remaining = uses_remaining - 1 \
         WHERE envelope_id = ? AND kind = 'uses' AND uses_remaining > 0",
    )
    .bind(envelope_id)
    .execute(pool)
    .await
    .map_err(|e| io::Error::other(format!("consume_use: {e}")))?;
    if res.rows_affected() == 0 {
        return Ok(false);
    }
    // Revoke as soon as the last activation is taken, so the grant is denied on
    // its next appearance without re-reading this table.
    let remaining: Option<(Option<i64>,)> =
        sqlx::query_as("SELECT uses_remaining FROM grant_lifetime WHERE envelope_id = ?")
            .bind(envelope_id)
            .fetch_optional(pool)
            .await
            .map_err(|e| io::Error::other(format!("consume_use read: {e}")))?;
    if matches!(remaining, Some((Some(n),)) if n <= 0) {
        revoke_envelope(pool, envelope_id).await?;
    }
    Ok(true)
}

/// Bind a `while_open` grant to the instance now activating it, if unbound.
pub async fn bind_instance(
    pool: &SqlitePool,
    envelope_id: &str,
    instance_token: &str,
) -> io::Result<()> {
    sqlx::query(
        "UPDATE grant_lifetime SET bound_instance = ? \
         WHERE envelope_id = ? AND kind = 'while_open' AND bound_instance IS NULL",
    )
    .bind(instance_token)
    .bind(envelope_id)
    .execute(pool)
    .await
    .map_err(|e| io::Error::other(format!("bind_instance: {e}")))?;
    Ok(())
}

/// Exhaust every `while_open` grant of an app whose instance has exited.
///
/// Called from each instance-teardown path (crash, terminate, uninstall). The
/// grant is revoked, so a later launch does not inherit it — "while open" ends
/// with the process, which is the whole of the promise.
///
/// **The envelope is deleted as well as revoked**, since
/// `TASK-a-file-the-person-opens-is-handed-to-the-app-that-opens-it` made this
/// the ordinary path rather than a rare one: the powerbox mints one envelope
/// per file the person opens, so a revocation row and a dead envelope per open
/// would accumulate for as long as the person used their computer. Revoking
/// first and deleting second, in that order, so an interrupted call leaves the
/// grant denied rather than live. The revocation row stays: it is what denies
/// a copy of the envelope held anywhere else, and it is the mechanism
/// `check_grant` already reads.
pub async fn exhaust_while_open_for_app(pool: &SqlitePool, app_id: &str) -> io::Result<()> {
    let ids: Vec<(String,)> = sqlx::query_as(
        "SELECT envelope_id FROM grant_lifetime WHERE app_id = ? AND kind = 'while_open'",
    )
    .bind(app_id)
    .fetch_all(pool)
    .await
    .map_err(|e| io::Error::other(format!("exhaust_while_open list: {e}")))?;
    for (id,) in ids {
        revoke_envelope(pool, &id).await?;
        delete_envelope(pool, &id).await?;
        sqlx::query("DELETE FROM grant_lifetime WHERE envelope_id = ?")
            .bind(&id)
            .execute(pool)
            .await
            .map_err(|e| io::Error::other(format!("exhaust_while_open clear: {e}")))?;
    }
    Ok(())
}

/// The lifetime kind recorded for an envelope: `"uses"`, `"while_open"`, or
/// `None` when it has no counted lifetime (an `UntilRevoked` or `Seconds` grant,
/// which this table does not track).
pub async fn lifetime_kind(pool: &SqlitePool, envelope_id: &str) -> io::Result<Option<String>> {
    let row: Option<(String,)> =
        sqlx::query_as("SELECT kind FROM grant_lifetime WHERE envelope_id = ?")
            .bind(envelope_id)
            .fetch_optional(pool)
            .await
            .map_err(|e| io::Error::other(format!("lifetime_kind: {e}")))?;
    Ok(row.map(|(k,)| k))
}

#[cfg(test)]
mod lifetime_tests {
    use super::*;
    use kotton_wire::GrantLifetime;

    /// An in-memory pool with just the tables these functions touch.
    async fn pool() -> SqlitePool {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        sqlx::query(
            "CREATE TABLE grant_lifetime (
                envelope_id TEXT PRIMARY KEY, app_id TEXT NOT NULL, kind TEXT NOT NULL,
                uses_remaining INTEGER, bound_instance TEXT, set_at INTEGER NOT NULL)",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query("CREATE TABLE revocation_list (envelope_id TEXT PRIMARY KEY, revoked_at INTEGER NOT NULL)")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(
            "CREATE TABLE app_grant_envelopes (
                id TEXT PRIMARY KEY, app_id TEXT NOT NULL, envelope_json TEXT NOT NULL,
                stored_at INTEGER NOT NULL)",
        )
        .execute(&pool)
        .await
        .unwrap();
        pool
    }

    /// A stored envelope with `id`, so exhaustion has something to delete.
    async fn stored(pool: &SqlitePool, app_id: &str, id: &str) {
        sqlx::query(
            "INSERT INTO app_grant_envelopes (id, app_id, envelope_json, stored_at) \
             VALUES (?, ?, '{}', 0)",
        )
        .bind(id)
        .bind(app_id)
        .execute(pool)
        .await
        .unwrap();
    }

    /// A `Uses(1)` grant is spent by one activation and denies the second — the
    /// "allow once" the consent standard asks for. `consume_use` revokes the
    /// envelope as it takes the last use, so the second access is caught by the
    /// ordinary revocation check (TASK-a-grant-cannot-be-once-or-while-open).
    #[tokio::test]
    async fn a_uses_grant_denies_its_second_activation() {
        let pool = pool().await;
        set_lifetime(&pool, "app", "env-once", GrantLifetime::Uses(1)).await.unwrap();
        assert_eq!(lifetime_kind(&pool, "env-once").await.unwrap().as_deref(), Some("uses"));

        // First activation is allowed and takes the last use.
        assert!(consume_use(&pool, "env-once").await.unwrap(), "first activation is allowed");
        // Taking the last use revokes the envelope.
        assert!(is_revoked(&pool, "env-once").await.unwrap(), "a spent Uses grant is revoked");
        // The second activation is denied.
        assert!(!consume_use(&pool, "env-once").await.unwrap(), "the second activation is denied");
    }

    /// The decrement is one atomic statement, so two activations racing on a
    /// one-use grant cannot both succeed — exactly one takes it.
    #[tokio::test]
    async fn concurrent_activations_cannot_both_take_one_use() {
        let pool = pool().await;
        set_lifetime(&pool, "app", "env", GrantLifetime::Uses(1)).await.unwrap();
        let (a, b) = tokio::join!(consume_use(&pool, "env"), consume_use(&pool, "env"));
        let taken = [a.unwrap(), b.unwrap()];
        assert_eq!(taken.iter().filter(|x| **x).count(), 1, "exactly one activation wins");
    }

    /// `Uses(2)` allows two activations, then denies.
    #[tokio::test]
    async fn a_uses_grant_honours_its_count() {
        let pool = pool().await;
        set_lifetime(&pool, "app", "env2", GrantLifetime::Uses(2)).await.unwrap();
        assert!(consume_use(&pool, "env2").await.unwrap());
        assert!(!is_revoked(&pool, "env2").await.unwrap(), "still has a use left");
        assert!(consume_use(&pool, "env2").await.unwrap());
        assert!(is_revoked(&pool, "env2").await.unwrap(), "spent after the second");
        assert!(!consume_use(&pool, "env2").await.unwrap());
    }

    /// A `WhileOpen` grant is revoked when its app's instance is torn down, so a
    /// later launch does not inherit it — "denies after the instance exits".
    #[tokio::test]
    async fn a_while_open_grant_is_revoked_when_the_instance_exits() {
        let pool = pool().await;
        set_lifetime(&pool, "sh.kotton.app", "env-wo", GrantLifetime::WhileOpen).await.unwrap();
        assert_eq!(lifetime_kind(&pool, "env-wo").await.unwrap().as_deref(), Some("while_open"));
        // Not consumed on activation — valid while the instance runs.
        assert!(!is_revoked(&pool, "env-wo").await.unwrap(), "valid while open");
        bind_instance(&pool, "env-wo", "instance-token-1").await.unwrap();
        // The instance exits.
        exhaust_while_open_for_app(&pool, "sh.kotton.app").await.unwrap();
        assert!(is_revoked(&pool, "env-wo").await.unwrap(), "revoked once the instance exits");
    }

    /// **And the grant is gone, not merely denied.**
    ///
    /// The powerbox mints one of these per file the person opens
    /// (`TASK-a-file-the-person-opens-is-handed-to-the-app-that-opens-it`), so a
    /// dead envelope left behind per open would accumulate for as long as the
    /// person used their computer. The revocation row stays — it is what denies
    /// a copy held anywhere else — and the envelope and its lifetime row do not.
    #[tokio::test]
    async fn an_exhausted_while_open_grant_is_deleted_and_not_only_revoked() {
        let pool = pool().await;
        stored(&pool, "sh.kotton.editor", "env-handed").await;
        set_lifetime(&pool, "sh.kotton.editor", "env-handed", GrantLifetime::WhileOpen)
            .await
            .unwrap();

        exhaust_while_open_for_app(&pool, "sh.kotton.editor").await.unwrap();

        let left: Vec<(String,)> =
            sqlx::query_as("SELECT id FROM app_grant_envelopes WHERE app_id = ?")
                .bind("sh.kotton.editor")
                .fetch_all(&pool)
                .await
                .unwrap();
        assert!(left.is_empty(), "the handed-over envelope outlived its instance: {left:?}");
        assert!(
            lifetime_kind(&pool, "env-handed").await.unwrap().is_none(),
            "and so did the row that says it is a while-open grant"
        );
        assert!(
            is_revoked(&pool, "env-handed").await.unwrap(),
            "the revocation stands, so a copy of the envelope held elsewhere is still denied"
        );
    }

    /// An app with no while-open grant loses nothing when its instance exits.
    ///
    /// The teardown path calls this for **every** app, so a rule written as
    /// "clear this app's envelopes" rather than "clear its while-open ones"
    /// would take away what the person approved at install and look exactly
    /// like an app that had lost its permissions.
    #[tokio::test]
    async fn exhaustion_leaves_an_apps_install_grant_alone() {
        let pool = pool().await;
        stored(&pool, "sh.kotton.editor", "env-install").await;
        set_lifetime(&pool, "sh.kotton.editor", "env-install", GrantLifetime::UntilRevoked)
            .await
            .unwrap();

        exhaust_while_open_for_app(&pool, "sh.kotton.editor").await.unwrap();

        let left: Vec<(String,)> =
            sqlx::query_as("SELECT id FROM app_grant_envelopes WHERE app_id = ?")
                .bind("sh.kotton.editor")
                .fetch_all(&pool)
                .await
                .unwrap();
        assert_eq!(left.len(), 1, "an install grant is not bound to an instance");
        assert!(!is_revoked(&pool, "env-install").await.unwrap());
    }

    /// The two lifetimes a clock already covers write no row, so nothing here can
    /// misreport them: `lifetime_kind` is `None` and neither consumes.
    #[tokio::test]
    async fn untracked_lifetimes_write_no_row() {
        let pool = pool().await;
        set_lifetime(&pool, "app", "env-rev", GrantLifetime::UntilRevoked).await.unwrap();
        set_lifetime(&pool, "app", "env-ttl", GrantLifetime::Seconds(60)).await.unwrap();
        assert!(lifetime_kind(&pool, "env-rev").await.unwrap().is_none());
        assert!(lifetime_kind(&pool, "env-ttl").await.unwrap().is_none());
        // consume_use is a no-op (and denies) for a grant with no uses row.
        assert!(!consume_use(&pool, "env-rev").await.unwrap());
        assert!(!is_revoked(&pool, "env-rev").await.unwrap(), "not revoked — just not a Uses grant");
    }
}
