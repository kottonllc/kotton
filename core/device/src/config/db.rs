// SPDX-License-Identifier: AGPL-3.0-or-later
//! DB access for the `device_config` key-value table.
//!
//! The table lives in `system/device.db` (device configuration is device
//! authority) and stores device-wide settings such as
//! coord/TURN URLs. Every function here takes the **device** pool from
//! [`super::device_db::open_device_db`], not the per-machine `agent.db` pool;
//! the same-named table still present in `agent.db` is a drained legacy shell,
//! to be deleted with that file.

/// sqlx errors as `io::Error`, so callers need not name sqlx.
///
/// Was `kuserd`'s `db::db_err`. Copied rather than moved: it is three lines, and the
/// daemon still has its own db modules that use it.
pub(super) fn db_err(e: sqlx::Error) -> std::io::Error {
    std::io::Error::other(e.to_string())
}
use super::NatNetworkConfig;
use sqlx::SqlitePool;
use std::io;

// ---------------------------------------------------------------------------
// Queries
// ---------------------------------------------------------------------------

/// Upsert a single key in `device_config`. Pass `None` to delete the key.
pub async fn set_key(db: &SqlitePool, key: &str, value: Option<&str>) -> io::Result<()> {
    match value {
        Some(v) => {
            sqlx::query("INSERT OR REPLACE INTO device_config (key, value) VALUES (?, ?)")
                .bind(key)
                .bind(v)
                .execute(db)
                .await
                .map_err(db_err)?;
        }
        None => {
            sqlx::query("DELETE FROM device_config WHERE key = ?")
                .bind(key)
                .execute(db)
                .await
                .map_err(db_err)?;
        }
    }
    Ok(())
}

/// Read a single key from `device_config`. Returns `None` if absent.
pub async fn get_key(db: &SqlitePool, key: &str) -> io::Result<Option<String>> {
    sqlx::query_scalar("SELECT value FROM device_config WHERE key = ?")
        .bind(key)
        .fetch_optional(db)
        .await
        .map_err(db_err)
}

/// Read `peer-listen-port` from `device_config`, returning `None` if absent or
/// if the stored value is not a valid `u16`.
pub async fn load_peer_listen_port(db: &SqlitePool) -> io::Result<Option<u16>> {
    let raw = get_key(db, "peer-listen-port").await?;
    Ok(raw.and_then(|s| s.parse::<u16>().ok()))
}

/// Who names the relay a daemon reserves at.
///
/// `Configured` is what a deployment does and the default everywhere: the
/// `relay_url` row in `device_config`, and nothing else — a device nobody told
/// has no relay.
/// An empty row is the person having chosen none. The other two exist because
/// a process that builds several daemons concurrently — the integration suite —
/// says which relay each reserves at when it constructs it, rather than through
/// anything process-wide.
///
/// A caller that states a relay is stating it about **this** daemon, so it wins
/// over the row.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum RelayChoice {
    /// The device's own configuration decides: the `device_config` row.
    #[default]
    Configured,
    /// This relay, whatever the row says; its key is asked of it as it is
    /// named, and a key it cannot prove refuses, as at every naming.
    At(String),
    /// No relay at all, whatever the row says.
    None,
}

impl RelayChoice {
    /// What a person setting their relay has said about it: a relay named is
    /// that one, and an empty name is leaving, as the row reads it.
    pub fn stated(url: Option<&str>) -> Self {
        match url {
            Some(url) if !url.is_empty() => Self::At(url.to_string()),
            _ => Self::None,
        }
    }
}

/// Read all NAT-related keys at once and return a populated `NatNetworkConfig`.
///
/// The relay comes from the device's own configuration; a caller that names one
/// for a single daemon wants [`load_nat_config_with`].
pub async fn load_nat_config(db: &SqlitePool) -> io::Result<NatNetworkConfig> {
    load_nat_config_with(db, RelayChoice::Configured).await
}

/// [`load_nat_config`], with the relay decided by `relay` rather than by the
/// device's configuration.
pub async fn load_nat_config_with(
    db: &SqlitePool,
    relay: RelayChoice,
) -> io::Result<NatNetworkConfig> {
    let mut nat = NatNetworkConfig::default();

    let rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT key, value FROM device_config WHERE key IN \
         ('relay_url','relay_url_previous','relay_url_previous_until','relay_key','relay_key_previous',\
          'turn_url','turn_username','turn_password','stun_urls')",
    )
    .fetch_all(db)
    .await
    .map_err(db_err)?;

    for (key, value) in rows {
        match key.as_str() {
            "relay_url" => nat.relay_url = value,
            "relay_url_previous" => nat.relay_url_previous = value,
            "relay_key" => nat.relay_key = Some(value).filter(|k| !k.is_empty()),
            "relay_key_previous" => nat.relay_key_previous = Some(value).filter(|k| !k.is_empty()),
            "relay_url_previous_until" => {
                nat.relay_url_previous_until = value.parse().unwrap_or(0)
            }
            "turn_url" => nat.turn_url = value,
            "turn_username" => nat.turn_username = value,
            "turn_password" => nat.turn_password = value,
            "stun_urls" => {
                let servers: Vec<String> = value
                    .split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_owned)
                    .collect();
                if !servers.is_empty() {
                    nat.stun_servers = servers;
                }
            }
            _ => {}
        }
    }

    // The row is the whole of the device's configuration. `KOTTON_RELAY_URL` is
    // not read as a deployment's default for a device nobody had told: every
    // device is told its relay by a person (`config relay set`, a code) or by a
    // ceremony (an invite's relay), and a vault by its owner's desktop (its
    // reach set), so a device nobody told has none. Read from the environment, a
    // relay the person cleared would come back, a process building several
    // daemons would read one test's relay into another's, and a vault would
    // reserve nowhere when the file a person ran did not carry it.
    //
    // A relay stated by the caller is named as every naming verb names one: the
    // relay is asked who it is and the key it proves is what the keys presented
    // there are held under (`kotton_peer::relay_keys`); a relay that shows none
    // is recorded by its address alone, as before relays had keys. It compares no
    // URLs: a relay has a key of its own and proves it.
    match relay {
        // Under the one policy every naming shares (`key_to_keep`, through
        // `learn_relay_key`): a relay that shows no key, or does not answer, is
        // recorded by its address alone; one that answers with a key it cannot
        // prove refuses — here, the daemon's construction, with the reason.
        RelayChoice::At(url) => {
            nat.relay_key = crate::config::ops::learn_relay_key(&url).await.map_err(|e| {
                io::Error::other(format!("the relay stated for this daemon cannot be named: {e}"))
            })?;
            nat.relay_url = url;
        }
        RelayChoice::None => {
            nat.relay_url.clear();
            nat.relay_key = None;
        }
        RelayChoice::Configured => {}
    }

    Ok(nat)
}
