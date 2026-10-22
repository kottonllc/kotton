// SPDX-License-Identifier: AGPL-3.0-or-later
//! Where this vault stands: its **reach set**, as its owner's desktop told it
//! (`TASK-the-desktop-tells-the-vault-which-relays-to-stand-at`, RFC-0084 V10–V12).
//!
//! **A vault is a device of the person's, as far as reach is concerned.** It
//! stands at the relays it was told to, the way a phone does, and it is told by
//! the one party that holds both operator keys — the desktop, over the operator
//! wire (`StandAt`), on the vault's `enrol` and whenever the set changes. The relay is
//! told nothing, and nothing in the vault's settings file names a relay: what
//! the vault stands at is here, in its own state, so a restart needs no desktop
//! and no file, and an install that rewrites `/etc/kotton/vault.env` yields the
//! same vault.
//!
//! Each relay of the set is **its key**, with an address as a hint and the
//! admission keys its rule reads: *mine*, which the vault presents there as one
//! of its operator's machines, and *invited*, which it hands each tenant in its
//! answer to `NodeRelay` and presents when it dials on a tenant's behalf. It
//! never hands *mine* to anyone. The keys are held in the reachability's keyring
//! under the relay's key (`kotton_peer::relay_keys`) — never under an address.
//!
//! **0.1 reserves at the first relay of the set.** The set is a set because
//! RFC-0083's open question on standing at several relays is open; the
//! reachability layer holds one relay and the one it is leaving, and the rest
//! of the set is kept, and handed back on `StandAt`'s next telling, until it
//! holds more. A move is a device's move (RFC-0083 R5): the relay being left is
//! held as the forwarding relay for its window, so a tenant who still dials it
//! lands, asks `NodeRelay`, and follows — nothing is re-paired.
//!
//! **An empty set is standing nowhere**, and it says so: no reservation, no
//! invite (`control::mint_invite`), and `NodeRelay` answered with no relay.
//! `KOTTON_RELAY_URL` is read by nothing (Done-when 4); a vault still carrying
//! it in its environment says, once at start, that it is not read.

use kotton_device::DeviceRuntime;
use kotton_net::rendezvous::AdmissionKey;
use kotton_peer::relay_keys::{relay_id, RelayId};
use kotton_wire::rendezvous::{RelayAdmission, Stand};
use sqlx::SqlitePool;
use std::io;

/// Whose the keys are in the keyring: the vault's, which is no person's.
const VAULT: &str = "";

/// Where the admission keys the set carries are kept: beside the machine db
/// and not in it, in a file born `0600` and replaced whole. The db holds which
/// relays the vault stands at — no secret — and is made with the process's
/// umask like every other table in it; *mine* is the key that admits a machine
/// as one of the operator's own, and it is kept where the vault's own key is
/// kept (`KOTTON_SECRETS=file`, `0600` under `KOTTON_BASE_DIR`), so on the
/// compose path, where the state directory is a volume and not a `0700`
/// `StateDirectory=`, the file's own mode is what keeps it the vault's.
const KEYS_FILE: &str = "relay-admission.json";

fn keys_path(runtime: &DeviceRuntime) -> std::path::PathBuf {
    runtime.base_dir().join("system").join(KEYS_FILE)
}

/// One relay's admission keys, as the file keeps them: by the relay's key.
struct KeptKeys {
    key: String,
    mine: String,
    invited: String,
}

/// The admission keys kept for the set, by relay key. A file in the form kept
/// before 2026-09-29 — one relay's keys by its URL — names no relay by its key:
/// it is deleted, and said, and the operator's next telling hands the keys again.
fn read_keys(runtime: &DeviceRuntime) -> Vec<KeptKeys> {
    read_keys_at(&keys_path(runtime))
}

fn read_keys_at(path: &std::path::Path) -> Vec<KeptKeys> {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Vec::new(),
        Err(e) => {
            tracing::warn!(error = %e, "the relay's admission keys could not be read; none are presented");
            return Vec::new();
        }
    };
    let kept = serde_json::from_slice::<serde_json::Value>(&bytes).ok().and_then(|v| {
        v.as_array()?
            .iter()
            .map(|e| {
                let f = |k: &str| e.get(k)?.as_str().map(str::to_string);
                Some(KeptKeys { key: f("key")?, mine: f("mine")?, invited: f("invited")? })
            })
            .collect::<Option<Vec<_>>>()
    });
    match kept {
        Some(all) => all,
        None => {
            let _ = std::fs::remove_file(path);
            tracing::info!(
                "the relay admission keys kept in the form before 2026-09-29 (by the relay's URL) are deleted; \
                 the operator's desktop hands them again when it next tells this vault where to stand"
            );
            Vec::new()
        }
    }
}

/// Keep the admission keys `set` carries, replacing what was kept — written to
/// a temporary file born `0600`, then renamed over the old one, so the file is
/// the old keys or the new ones and never readable by others. A set carrying
/// none removes the file.
fn write_keys(runtime: &DeviceRuntime, set: &[Stand]) -> io::Result<()> {
    write_keys_at(&keys_path(runtime), set)
}

fn write_keys_at(path: &std::path::Path, set: &[Stand]) -> io::Result<()> {
    let kept: Vec<KeptKeys> = set
        .iter()
        .filter_map(|s| match (&s.mine, &s.invited) {
            (Some(m), Some(i)) => Some(KeptKeys {
                key: s.key.trim().to_ascii_lowercase(),
                mine: m.expose().to_string(),
                invited: i.expose().to_string(),
            }),
            _ => None,
        })
        .collect();
    if kept.is_empty() {
        return match std::fs::remove_file(path) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
            _ => Ok(()),
        };
    }
    let json: Vec<serde_json::Value> = kept
        .iter()
        .map(|k| serde_json::json!({ "key": k.key, "mine": k.mine, "invited": k.invited }))
        .collect();
    write_private(path, &serde_json::to_vec(&json).map_err(io::Error::other)?)
}

fn write_private(path: &std::path::Path, bytes: &[u8]) -> io::Result<()> {
    use std::io::Write as _;
    if let Some(dir) = path.parent() {
        kotton_common::fs::create_dir_all_owner_only(dir)?;
    }
    let tmp = path.with_extension("tmp");
    let _ = std::fs::remove_file(&tmp);
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    let mut f = opts.open(&tmp)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    drop(f);
    std::fs::rename(&tmp, path)
}

fn db_err(e: sqlx::Error) -> io::Error {
    io::Error::other(e.to_string())
}

/// The table the set is kept in, beside the vault's other tables.
pub async fn init(db: &SqlitePool) -> io::Result<()> {
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS reach_set (
            pos     INTEGER PRIMARY KEY,
            key     TEXT NOT NULL,
            hint    TEXT NOT NULL,
            told_at INTEGER NOT NULL
        )",
    )
    .execute(db)
    .await
    .map_err(db_err)?;
    Ok(())
}

/// The set as it was last told, first relay first, as the machine db keeps it:
/// each relay by its key and hint, and no admission key (those are in their
/// own file). Empty when nobody has told this vault anything.
pub async fn read(db: &SqlitePool) -> io::Result<Vec<Stand>> {
    let rows: Vec<(String, String)> = sqlx::query_as("SELECT key, hint FROM reach_set ORDER BY pos")
        .fetch_all(db)
        .await
        .map_err(db_err)?;
    Ok(rows
        .into_iter()
        .map(|(key, hint)| Stand { key, hint, mine: None, invited: None })
        .collect())
}

/// [`read`], with the admission keys kept for each relay beside it.
async fn read_whole(runtime: &DeviceRuntime, db: &SqlitePool) -> io::Result<Vec<Stand>> {
    let keys = read_keys(runtime);
    Ok(read(db)
        .await?
        .into_iter()
        .map(|mut s| {
            if let Some(k) = keys.iter().find(|k| k.key == s.key) {
                s.mine = Some(kotton_wire::ipc::SecretText::new(k.mine.clone()));
                s.invited = Some(kotton_wire::ipc::SecretText::new(k.invited.clone()));
            }
            s
        })
        .collect())
}

/// One relay of a set, read: its key, and its two admission keys when its rule
/// reads them. Refused — with the sentence the operator reads — for a key that
/// is not one, an empty hint, or an admission key that does not parse; a relay
/// with one admission key and not the other is refused too, since a rule reads
/// both or neither.
fn checked(stand: &Stand) -> Result<(RelayId, Option<(AdmissionKey, AdmissionKey)>), String> {
    let key = relay_id(Some(&stand.key)).ok_or_else(|| format!("'{}' is not a relay's key — 64 hex", stand.key))?;
    if stand.hint.trim().is_empty() {
        return Err(format!("the relay {} is told with no address to find it at", stand.key));
    }
    let admission = match (&stand.mine, &stand.invited) {
        (None, None) => None,
        (Some(m), Some(i)) => match (AdmissionKey::parse(m.expose()), AdmissionKey::parse(i.expose())) {
            (Some(m), Some(i)) => Some((m, i)),
            _ => return Err("an admission key is 32 bytes, base64url".to_string()),
        },
        _ => return Err(format!("the relay {} is told one admission key of its two", stand.key)),
    };
    Ok((key, admission))
}

/// Take `set` as this vault's whole reach set: check it, ask each relay at its
/// hint whether it is the relay named — under the one policy every verb that
/// names a relay shares (`kotton_peer::relay_key::key_to_keep`): another key at
/// the address refuses the set, a relay that does not answer is kept as named —
/// then keep it in place of what was held, and stand where it says. Nothing is
/// changed unless all of it is taken.
pub async fn stand_at(
    runtime: &DeviceRuntime,
    db: &SqlitePool,
    device_db: &SqlitePool,
    set: Vec<Stand>,
) -> Result<(), String> {
    for stand in &set {
        let (key, _) = checked(stand)?;
        let proved = kotton_peer::relay_key::prove_relay(stand.hint.trim(), Some(&key)).await;
        kotton_peer::relay_key::key_to_keep(Some(key), proved)
            .map_err(|e| format!("this vault was told to stand at a relay it cannot find: {e}"))?;
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64);
    let mut tx = db.begin().await.map_err(|e| e.to_string())?;
    sqlx::query("DELETE FROM reach_set").execute(&mut *tx).await.map_err(|e| e.to_string())?;
    for (pos, stand) in set.iter().enumerate() {
        sqlx::query("INSERT INTO reach_set (pos, key, hint, told_at) VALUES (?, ?, ?, ?)")
            .bind(pos as i64)
            .bind(stand.key.trim().to_ascii_lowercase())
            .bind(stand.hint.trim())
            .bind(now)
            .execute(&mut *tx)
            .await
            .map_err(|e| e.to_string())?;
    }
    tx.commit().await.map_err(|e| e.to_string())?;
    // The keys after the set is committed, so a failed commit never leaves
    // keys on disk ahead of the relays they belong to. A write that fails after
    // it leaves the set kept with the keys it had before — keys are found by
    // relay key, so a relay the set no longer names is never presented with
    // them — and the telling answers the failure, so the operator tells again.
    write_keys(runtime, &set).map_err(|e| format!("the reach set is kept and its admission keys are not: {e}"))?;
    // The first relay is where the reachability reserves. When it moved, it is
    // written as a device writes its relay, so the relay being left is kept as
    // the forwarding relay for its window (RFC-0083 R5), and read back as the
    // device reads it. When it did not — a telling that only changes the keys,
    // a rotation — the reservations stay where they are and present the new key
    // at their next attempt, which reads the keyring every time; moving them
    // would drop, for nothing, reservations the relay admits.
    let first = set.first();
    let now_at = runtime.reachability().nat();
    let moved = first.map(|s| (s.hint.trim().to_string(), Some(s.key.trim().to_ascii_lowercase())))
        != Some((now_at.relay_url.clone(), now_at.relay_key.clone())).filter(|(u, _)| !u.is_empty());
    let nat = if moved {
        kotton_device::config::ops::set_coord_url(
            device_db,
            Some(&now_at.relay_url),
            first.map(|s| s.hint.trim()),
            first.map(|s| s.key.trim().to_ascii_lowercase()).as_deref(),
        )
        .await
        .map_err(|e| e.to_string())?;
        Some(kotton_device::config::db::load_nat_config(device_db).await.map_err(|e| e.to_string())?)
    } else {
        None
    };
    apply(runtime, &set, nat).await;
    tracing::info!(relays = set.len(), "this vault was told where to stand");
    Ok(())
}

/// Stand where `set` says: its keys into the keyring under each relay's key,
/// and — given the reachability config `nat` to move — the first relay as where
/// it reserves, none when the set is empty. What start and a telling both do.
pub async fn apply(runtime: &DeviceRuntime, set: &[Stand], nat: Option<kotton_peer::nat::NatNetworkConfig>) {
    let keys = runtime.reachability().relay_keys();
    keys.forget(VAULT);
    for stand in set {
        match checked(stand) {
            // Held with no address of its own: the relay a vault reserves at
            // is its own by the first stand of its set, which is its
            // reachability record (below), and that is unchanged.
            Ok((relay, Some((mine, invited)))) => keys.hold_as_operator(VAULT, &relay, None, mine, invited),
            Ok((_, None)) => {}
            Err(e) => tracing::warn!(error = %e, "a relay this vault keeps does not read; its keys are not presented"),
        }
    }
    let Some(mut nat) = nat else { return };
    match set.first() {
        Some(first) => {
            nat.relay_url = first.hint.trim().to_string();
            nat.relay_key = Some(first.key.trim().to_ascii_lowercase());
        }
        None => {
            nat.relay_url.clear();
            nat.relay_key = None;
        }
    }
    if let Err(e) = runtime.reconfigure_network(nat).await {
        tracing::warn!(error = %e, "the reach set is kept and the network did not take it");
    }
}

/// The vault's reach at start: the set it keeps, stood at. Says so when the set
/// is empty — and when the environment still carries the variable that named a
/// relay before, which nothing reads.
pub async fn restore(runtime: &DeviceRuntime, db: &SqlitePool, nat: kotton_peer::nat::NatNetworkConfig) -> io::Result<()> {
    let set = read_whole(runtime, db).await?;
    if set.is_empty() {
        tracing::info!("this vault stands at no relay: its operator's desktop has not told it where to stand");
        if std::env::var("KOTTON_RELAY_URL").is_ok_and(|v| !v.trim().is_empty()) {
            tracing::warn!(
                "KOTTON_RELAY_URL is set in this vault's environment and is not read — a vault stands where its \
                 owner's desktop tells it (its `enrol`); the line can be deleted from /etc/kotton/vault.env"
            );
        }
    }
    apply(runtime, &set, Some(nat)).await;
    Ok(())
}

/// What a tenant who asked where this vault reserves is told: the first relay's
/// address and key, and the *invited* key for it — never *mine*.
pub fn for_tenant(runtime: &DeviceRuntime) -> (Option<String>, Option<String>, Option<RelayAdmission>) {
    let nat = runtime.reachability().nat();
    let url = Some(nat.relay_url).filter(|u| !u.is_empty());
    let admission = invited(runtime).map(|k| RelayAdmission {
        present: kotton_wire::ipc::SecretText::new(k.to_text()),
        offer: None,
    });
    (url, nat.relay_key, admission)
}

/// The *invited* key for the relay this vault reserves at, as a key to present —
/// what a tenant's device would present there, and what the vault presents when
/// it dials on a tenant's behalf (`carry`). Never *mine*: a carried dial is the
/// tenant's, not the operator's.
pub fn invited(runtime: &DeviceRuntime) -> Option<AdmissionKey> {
    let relay = relay_id(runtime.reachability().nat().relay_key.as_deref())?;
    runtime.reachability().relay_keys().offer_for(VAULT, &relay)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stand(key: &str, mine: Option<&str>, invited: Option<&str>) -> Stand {
        Stand {
            key: key.into(),
            hint: "http://r:7700".into(),
            mine: mine.map(kotton_wire::ipc::SecretText::new),
            invited: invited.map(kotton_wire::ipc::SecretText::new),
        }
    }

    /// A relay of a set is its key, whole; its admission keys are both or
    /// neither; and a key that is not one is refused by name.
    #[test]
    fn a_relay_of_the_set_is_a_key_with_both_admission_keys_or_neither() {
        let k = hex::encode([1u8; 32]);
        let a = AdmissionKey::from_bytes([2u8; 32]).to_text();
        assert!(matches!(checked(&stand(&k, None, None)), Ok((r, None)) if r == [1u8; 32]));
        assert!(matches!(checked(&stand(&k, Some(&a), Some(&a))), Ok((_, Some(_)))));
        assert!(checked(&stand(&k, Some(&a), None)).is_err());
        assert!(checked(&stand(&k, Some("nope"), Some(&a))).is_err());
        assert!(checked(&stand("http://r:7700", None, None)).is_err(), "an address is not a relay");
        let mut blank = stand(&k, None, None);
        blank.hint = " ".into();
        assert!(checked(&blank).is_err());
    }

    /// **The admission keys are kept in a file of the vault's alone**, not in
    /// the machine db: born `0600`, read back by relay key, removed when a set
    /// carries none; and a file in the form kept before 2026-09-29 — one
    /// relay's keys by its URL — is deleted when it is read, not left behind.
    #[test]
    fn the_admission_keys_are_a_0600_file_and_the_old_form_is_deleted() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("system").join(KEYS_FILE);
        let k = hex::encode([1u8; 32]);
        let a = AdmissionKey::from_bytes([2u8; 32]).to_text();
        write_keys_at(&path, &[stand(&k, Some(&a), Some(&a)), stand(&hex::encode([3u8; 32]), None, None)]).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        }
        let kept = read_keys_at(&path);
        assert_eq!(kept.iter().map(|k| k.key.as_str()).collect::<Vec<_>>(), [k.as_str()]);
        write_keys_at(&path, &[stand(&k, None, None)]).unwrap();
        assert!(!path.exists(), "a set with no keys keeps no file");

        std::fs::write(&path, r#"{"relay":"http://r:7700","mine":"m","invited":"i"}"#).unwrap();
        assert!(read_keys_at(&path).is_empty());
        assert!(!path.exists(), "the file kept by URL is deleted");
    }
}
