// SPDX-License-Identifier: AGPL-3.0-or-later
//! Reading and writing this machine's configuration.
//!
//! ## Why these are here and not in the daemon
//!
//! These fifteen operations lived in `kuserd`'s `handlers/device_config.rs`, and every
//! one of them returned `io::Result<UserResponse>` — the 147-variant IPC enum. That is
//! what kept them there: not the logic, which is "read a key, write a key", but the
//! response type wrapped around it.
//!
//! Moving them unchanged would have put IPC response construction inside the crate that
//! models *the machine*, which is backwards. So the split is at the wire: an operation
//! here returns what it found, and the daemon's handler decides which `UserResponse`
//! variant carries it. Setting a coordinator URL is the machine's business; naming the
//! frame that reports it is not.
//!
//! `RendezvousStatusInfo` and `ConfigItem` are still `kotton_wire` types. They are
//! *data*, shared by both sides, and naming them costs nothing — it is the envelope that
//! did not belong here.

use std::io;

use kotton_wire::ipc::ConfigItem;
use kotton_wire::rendezvous::RendezvousStatusInfo;
use sqlx::SqlitePool;

use super::db as device_config_db;

/// The `device_config` key holding the coordinator URL.
const RELAY_URL_KEY: &str = "relay_url";
/// The `device_config` key holding the TURN relay URL.
const TURN_URL_KEY: &str = "turn_url";
/// The `device_config` key holding comma-separated STUN URLs.
const STUN_URLS_KEY: &str = "stun_urls";
/// The `device_config` key holding this machine's human name.
const DEVICE_NAME_KEY: &str = "device-name";
/// The `device_config` key that decides whether this machine runs a model.
/// Read at boot by `kuserd`, which supervises `kinferd` only when it
/// says `true`.
const INFERENCE_ENABLED_KEY: &str = "inference.enabled";

/// The `device_config` keys holding the previous relay and when its forwarding
/// window closes.
const RELAY_URL_PREVIOUS_KEY: &str = "relay_url_previous";
const RELAY_URL_PREVIOUS_UNTIL_KEY: &str = "relay_url_previous_until";

/// The `device_config` keys holding the key the relay proved when the device
/// learned it, beside its URL, and the previous relay's beside its.
/// Absent when none was shown.
const RELAY_KEY_KEY: &str = "relay_key";
const RELAY_KEY_PREVIOUS_KEY: &str = "relay_key_previous";

/// How long a device keeps holding reservations at the relay it left, so a
/// peer that still names it lands there and learns the new one. Thirty days:
/// the cost is two idle sockets per paired peer, and the cost of a shorter
/// window is a phone that slept through it and can no longer find home.
pub const RELAY_FORWARDING_WINDOW_SECS: i64 = 30 * 24 * 60 * 60;

/// Set or clear the relay URL.
///
/// A change is a forwarding address: `leaving` — the relay the device holds
/// reservations at *now*, which the caller reads from the live config — is
/// kept as the previous one for [`RELAY_FORWARDING_WINDOW_SECS`], and the
/// reservation listener holds at both until the window closes.
///
/// Clearing writes an **empty** row rather than deleting it. A missing row is a
/// device nobody has told, and an empty one is a person who chose no relay;
/// neither has a relay, and nothing fills one from the environment. Every
/// reader of the row reads empty as not configured.
///
/// `key` is what the relay proved when it was named
/// ([`kotton_peer::relay_key::prove_relay`]), hex, kept beside the URL; `None`
/// when it showed none, which clears any key the row held for another relay.
/// Leaving a relay moves its key beside its URL in the forwarding slot.
pub async fn set_coord_url(
    db: &SqlitePool,
    leaving: Option<&str>,
    url: Option<&str>,
    key: Option<&str>,
) -> io::Result<()> {
    let leaving = leaving.filter(|u| !u.is_empty());
    let same = restates(leaving, url);
    write_relay(db, leaving, same, url, key).await
}

/// Whether `url` names the relay being left — the one comparison a relay's
/// naming makes. It decides both the forwarding slot and whether the key
/// recorded for that relay is expected: re-stating a recorded relay is not first sight.
fn restates(leaving: Option<&str>, url: Option<&str>) -> bool {
    leaving.is_some() && url.map(str::trim) == leaving
}

async fn write_relay(
    db: &SqlitePool,
    leaving: Option<&str>,
    same: bool,
    url: Option<&str>,
    key: Option<&str>,
) -> io::Result<()> {
    let recorded = device_config_db::get_key(db, RELAY_KEY_KEY).await?;
    if let (Some(prev), false) = (leaving, same) {
        let until = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
            + RELAY_FORWARDING_WINDOW_SECS;
        device_config_db::set_key(db, RELAY_URL_PREVIOUS_KEY, Some(prev)).await?;
        device_config_db::set_key(db, RELAY_URL_PREVIOUS_UNTIL_KEY, Some(&until.to_string())).await?;
        device_config_db::set_key(db, RELAY_KEY_PREVIOUS_KEY, recorded.as_deref()).await?;
    }
    // A relay re-stated keeps the key recorded for it unless another was
    // proved; forgetting it is `config relay clear` and then `set`, never a
    // silent write of nothing.
    let key = match (same, key) {
        (true, None) => recorded,
        (_, key) => key.map(str::to_string),
    };
    let key = key.filter(|_| url.is_some_and(|u| !u.is_empty()));
    device_config_db::set_key(db, RELAY_KEY_KEY, key.as_deref()).await?;
    device_config_db::set_key(db, RELAY_URL_KEY, Some(url.unwrap_or(""))).await
}

/// Name the device's relay: `config relay set`, a relay paired by name, an
/// invite's relay at `drive enrol`. The relay at `url` is asked who it is and
/// the answer recorded beside the URL.
///
/// A relay the device already holds — `url` is the one being `leaving` — is
/// asked with its recorded key expected, under the one policy every naming verb
/// shares ([`kotton_peer::relay_key::key_to_keep`]): proved, it is kept; silent,
/// the recorded key stays; another key refuses the verb and nothing is written.
/// Any other relay is
/// first sight, as [`learn_relay_key`] says. `url` of `None` or empty clears the
/// relay and its key. Answers the key now recorded, hex.
pub async fn name_relay(
    db: &SqlitePool,
    leaving: Option<&str>,
    url: Option<&str>,
) -> io::Result<Option<String>> {
    let leaving = leaving.filter(|u| !u.is_empty());
    let same = restates(leaving, url);
    let key = match url.map(str::trim).filter(|u| !u.is_empty()) {
        None => None,
        Some(u) => {
            let named = if same {
                device_config_db::get_key(db, RELAY_KEY_KEY)
                    .await?
                    .and_then(|k| hex::decode(k).ok())
                    .and_then(|b| <[u8; 32]>::try_from(b).ok())
            } else {
                None
            };
            let proved = kotton_peer::relay_key::prove_relay(u, named.as_ref()).await;
            kotton_peer::relay_key::key_to_keep(named, proved)
                .map_err(io::Error::other)?
                .map(hex::encode)
        }
    };
    write_relay(db, leaving, same, url, key.as_deref()).await?;
    device_config_db::get_key(db, RELAY_KEY_KEY).await
}

/// Stand this device at the relay a code names — a relay's line, or a relay's
/// invite — held to the key the code names: the
/// relay at `url` must prove `key`, or nothing is written and the refusal says
/// so. Nothing about the relay is first sight, because the code named its key.
/// `leaving` is the relay the device holds reservations at now, which becomes
/// the forwarding address as at [`name_relay`].
pub async fn stand_at(db: &SqlitePool, leaving: Option<&str>, url: &str, key: [u8; 32]) -> io::Result<()> {
    let url = url.trim();
    kotton_peer::relay_key::prove_relay(url, Some(&key)).await.map_err(|e| {
        io::Error::other(format!(
            "the relay at {url} did not prove the key its code names, so nothing changed — this device is \
             still where it was ({e})"
        ))
    })?;
    let leaving = leaving.filter(|u| !u.is_empty());
    let same = restates(leaving, Some(url));
    write_relay(db, leaving, same, Some(url), Some(&hex::encode(key))).await
}

/// Ask the relay at `url` who it is, at the moment a device learns it — `config
/// relay set`, a relay paired by name, an invite's relay at `drive enrol`, `relay
/// enrol` — and answer the key to record beside the URL, hex.
///
/// First sight, so no key is expected: a relay that shows none, or does not
/// answer, is `Ok(None)` and the URL is recorded alone, as it was before relays
/// had keys. A relay that answers with a key it cannot prove is refused.
pub async fn learn_relay_key(url: &str) -> io::Result<Option<String>> {
    kotton_peer::relay_key::prove_relay(url, None)
        .await
        .map(|k| k.map(hex::encode))
        .map_err(io::Error::other)
}

/// The relay the person has set, or `None` when they have set none — whether
/// nobody ever wrote the row or they cleared it, which [`set_coord_url`] writes
/// as an empty value.
pub async fn relay_url(db: &SqlitePool) -> io::Result<Option<String>> {
    Ok(device_config_db::get_key(db, RELAY_URL_KEY)
        .await?
        .filter(|u| !u.is_empty()))
}

/// This machine's coordinator configuration.
///
/// `last_push`, `last_lookup` and `server_reachable` are always `None` — `nat.rs`
/// tracks them, and nothing carries them here. Stated
/// rather than left to be discovered: a status field that is structurally unset reads
/// like a bug when it is a gap.
pub async fn coord_status(db: &SqlitePool) -> io::Result<RendezvousStatusInfo> {
    Ok(RendezvousStatusInfo {
        url: relay_url(db).await?,
        last_push: None,
        last_lookup: None,
        server_reachable: None,
    })
}

/// Set or clear the TURN relay URL.
pub async fn set_turn_url(db: &SqlitePool, url: Option<&str>) -> io::Result<()> {
    device_config_db::set_key(db, TURN_URL_KEY, url).await
}

/// Turn this machine's inference runtime on or off.
///
/// Named, like every other writer in this file, rather than reached through a
/// generic "set any key": a generic setter would let a caller write a key no
/// reader knows about, and a key with no writer is a switch with no handle.
///
/// The change takes effect when `kuserd` next starts. `supervise_kinferd` is
/// spawned at boot and nothing here reaches into a running daemon, which is the
/// same bargain `quic-gateway.enabled` makes.
pub async fn set_inference(db: &SqlitePool, enabled: bool) -> io::Result<()> {
    let v = if enabled { "true" } else { "false" };
    device_config_db::set_key(db, INFERENCE_ENABLED_KEY, Some(v)).await
}

/// Whether this machine runs a model. **Off** on a machine nobody has told.
///
/// Off by default because until a model is installed there is nothing for the
/// runtime to load, and a process with nothing to do is a cost with no benefit.
/// What should replace this is named: once a
/// model is a record in the person's store, *is a model installed?* is the
/// condition, exactly as *are there paired nodes?* is `ksyncd`'s.
pub async fn inference(db: &SqlitePool) -> io::Result<bool> {
    Ok(device_config_db::get_key(db, INFERENCE_ENABLED_KEY)
        .await?
        .map(|v| v == "true")
        .unwrap_or(false))
}

/// Every device-level config key, with what it enables and how to set it.
pub async fn config_items(db: &SqlitePool) -> io::Result<Vec<ConfigItem>> {
    let relay_url = relay_url(db).await?;
    let turn_url = device_config_db::get_key(db, TURN_URL_KEY).await?;
    let stun_urls = device_config_db::get_key(db, STUN_URLS_KEY).await?;
    let inference = device_config_db::get_key(db, INFERENCE_ENABLED_KEY).await?;

    Ok(vec![
        ConfigItem {
            configured: relay_url.is_some(),
            value: relay_url,
            key: RELAY_URL_KEY.to_string(),
            capability: "peer address exchange and DM store-and-forward".to_string(),
            command: "kotton config relay set <url>".to_string(),
        },
        ConfigItem {
            configured: turn_url.is_some(),
            value: turn_url,
            key: TURN_URL_KEY.to_string(),
            capability: "TURN relay for NAT traversal when QUIC direct fails".to_string(),
            command: "kotton node turn set <url>".to_string(),
        },
        ConfigItem {
            configured: stun_urls.is_some(),
            value: stun_urls,
            key: STUN_URLS_KEY.to_string(),
            capability: "STUN address discovery for peer-to-peer connections".to_string(),
            command: "kotton node stun set <url>[,<url>...]".to_string(),
        },
        ConfigItem {
            configured: inference.is_some(),
            value: inference,
            key: INFERENCE_ENABLED_KEY.to_string(),
            capability: "a model running on this machine, under your own keys (RFC-0085)"
                .to_string(),
            command: "kotton config inference set <on|off>".to_string(),
        },
    ])
}

/// What a gateway binds when nobody has said otherwise.
///
/// `loopback`, not `all`: the value you get by not deciding must be the safe end of
/// the range. PostgreSQL ships `listen_addresses = localhost` for the same reason.
/// Devices configured before this default changed keep whatever they stored.
pub const DEFAULT_BIND: &str = "loopback";

/// This machine's QUIC gateway settings.
pub struct QuicGateway {
    pub enabled: bool,
    pub port: u16,
    pub bind: String,
    pub allow: Option<String>,
}

/// Refuse a bind/allow pair that does not parse as an exposure.
///
/// Travels with the setter rather than staying in the daemon: a validator separated
/// from the write it guards is a validator someone can route around.
fn validate_exposure(bind: Option<&str>, allow: Option<&str>) -> io::Result<()> {
    // `Exposure::parse` needs a bind value; when only the allow-list is being set,
    // check it against a scope that always parses so the error names the real field.
    let probe_bind = bind.unwrap_or(DEFAULT_BIND);
    kotton_common::listen::Exposure::parse(probe_bind, allow)
        .map(|_| ())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))
}

/// Persist QUIC gateway configuration. `None` fields leave the stored value alone.
pub async fn set_quic_gateway(
    db: &SqlitePool,
    enabled: Option<bool>,
    port: Option<u16>,
    bind: Option<String>,
    allow: Option<String>,
) -> io::Result<()> {
    validate_exposure(bind.as_deref(), allow.as_deref())?;
    if let Some(v) = enabled {
        let v = if v { "true" } else { "false" };
        device_config_db::set_key(db, "quic-gateway.enabled", Some(v)).await?;
    }
    if let Some(p) = port {
        device_config_db::set_key(db, "quic-gateway.port", Some(p.to_string().as_str())).await?;
    }
    if let Some(b) = bind {
        device_config_db::set_key(db, "quic-gateway.bind", Some(b.as_str())).await?;
    }
    if let Some(a) = allow {
        device_config_db::set_key(db, "quic-gateway.allow", Some(a.as_str())).await?;
    }
    Ok(())
}

/// Read QUIC gateway configuration, with the defaults an unset machine gets.
pub async fn quic_gateway(db: &SqlitePool) -> io::Result<QuicGateway> {
    Ok(QuicGateway {
        enabled: device_config_db::get_key(db, "quic-gateway.enabled")
            .await?
            .map(|v| v == "true")
            .unwrap_or(false),
        port: device_config_db::get_key(db, "quic-gateway.port")
            .await?
            .and_then(|v| v.parse().ok())
            .unwrap_or(7443),
        bind: device_config_db::get_key(db, "quic-gateway.bind")
            .await?
            .unwrap_or_else(|| DEFAULT_BIND.to_string()),
        allow: device_config_db::get_key(db, "quic-gateway.allow").await?,
    })
}

/// This machine's web shell settings.
pub struct WebShell {
    pub enabled: bool,
    pub port: u16,
    pub bind: String,
    pub allow: Option<String>,
    pub static_dir: Option<String>,
}

impl WebShell {
    /// The environment `khttpd` is spawned with — its whole configuration, handed
    /// over at spawn rather than fetched afterwards.
    ///
    /// `khttpd` used to read this back over IPC with `WebShellStatus`, which is
    /// `Local`-tier because a gateway must never *reconfigure* itself. The same
    /// floor also stopped it *reading* the configuration it was started for, so it
    /// ran on defaults whatever the operator set. Handing the material over here
    /// removes the reach instead of loosening the check: the sidecar's IPC scope
    /// shrinks to the one verb a gateway exists for, and the trust floor is not
    /// touched.
    ///
    /// Every key is set explicitly, including the defaults, so `khttpd` never has a
    /// reason to guess. A gateway that guesses is how `lan` once came to mean
    /// `public`.
    pub fn spawn_env(&self) -> Vec<(&'static str, String)> {
        let mut env = vec![
            ("KHTTPD_PORT", self.port.to_string()),
            ("KHTTPD_BIND", self.bind.clone()),
        ];
        if let Some(allow) = &self.allow {
            env.push(("KHTTPD_ALLOW", allow.clone()));
        }
        if let Some(dir) = &self.static_dir {
            env.push(("KHTTPD_STATIC_DIR", dir.clone()));
        }
        env
    }
}

/// Persist web shell configuration. `None` fields leave the stored value alone.
///
/// Shares [`validate_exposure`] with the QUIC gateway above — the same bind/allow
/// pair means the same thing whichever listener it configures, and having one
/// validator is why it moved here rather than being copied.
pub async fn set_web_shell(
    db: &SqlitePool,
    enabled: Option<bool>,
    port: Option<u16>,
    bind: Option<String>,
    static_dir: Option<String>,
    allow: Option<String>,
) -> io::Result<()> {
    validate_exposure(bind.as_deref(), allow.as_deref())?;
    if let Some(v) = enabled {
        let v = if v { "true" } else { "false" };
        device_config_db::set_key(db, "web-shell.enabled", Some(v)).await?;
    }
    if let Some(p) = port {
        device_config_db::set_key(db, "web-shell.port", Some(p.to_string().as_str())).await?;
    }
    if let Some(b) = bind {
        device_config_db::set_key(db, "web-shell.bind", Some(b.as_str())).await?;
    }
    if let Some(d) = static_dir {
        device_config_db::set_key(db, "web-shell.static-dir", Some(d.as_str())).await?;
    }
    if let Some(a) = allow {
        device_config_db::set_key(db, "web-shell.allow", Some(a.as_str())).await?;
    }
    Ok(())
}

/// Read web shell configuration, with the defaults an unset machine gets.
pub async fn web_shell(db: &SqlitePool) -> io::Result<WebShell> {
    Ok(WebShell {
        enabled: device_config_db::get_key(db, "web-shell.enabled")
            .await?
            .map(|v| v == "true")
            .unwrap_or(false),
        port: device_config_db::get_key(db, "web-shell.port")
            .await?
            .and_then(|v| v.parse().ok())
            .unwrap_or(8443),
        bind: device_config_db::get_key(db, "web-shell.bind")
            .await?
            .unwrap_or_else(|| DEFAULT_BIND.to_string()),
        allow: device_config_db::get_key(db, "web-shell.allow").await?,
        static_dir: device_config_db::get_key(db, "web-shell.static-dir").await?,
    })
}




/// Admit a browser device key for `user_id` under `name`. Returns the
/// row id, which is the credential id a `Principal::Browser` carries.
pub async fn add_browser_device(
    db: &SqlitePool,
    user_id: &str,
    name: &str,
    device_pub: &[u8; 32],
) -> io::Result<String> {
    super::web_shell_db::add_browser_device(db, user_id, name, device_pub).await
}

/// The credential id for an admitted browser device key, touching its last-used
/// timestamp; `None` if the key is not registered for `user_id`.
pub async fn find_browser_device_id(
    db: &SqlitePool,
    user_id: &str,
    device_pub: &[u8; 32],
) -> io::Result<Option<String>> {
    super::web_shell_db::find_browser_device(db, user_id, device_pub).await
}

/// Every browser device admitted for `user_id`, oldest first.
pub async fn list_browser_devices(
    db: &SqlitePool,
    user_id: &str,
) -> io::Result<Vec<kotton_wire::ipc::types::BrowserDevice>> {
    super::web_shell_db::list_browser_devices(db, user_id).await
}

/// Forget the browser device `(user_id, name)`, returning its credential id, or
/// `None` if no browser by that name was admitted. Its next visit is refused
/// before anything is sealed to it; its live sessions are the caller's to end.
pub async fn revoke_browser_device(
    db: &SqlitePool,
    user_id: &str,
    name: &str,
) -> io::Result<Option<String>> {
    super::web_shell_db::revoke_browser_device(db, user_id, name).await
}


/// This machine's signing key bytes for `user_id`, as presented in its device cert.
pub fn device_signing_key(
    user_id: &str,
    secrets: &dyn kotton_sys::secret::SecretsStore,
) -> io::Result<Vec<u8>> {
    let signing_key = kotton_peer::daemon::nodes::load_signing_key(user_id, secrets)?;
    Ok(signing_key.to_bytes().to_vec())
}

/// This device's human name — the label it announces to peers when pairing.
///
/// Returns the stored value, else the OS hostname, which is persisted on first read
/// so it is stable and can then be edited.
pub async fn resolve_device_name(db: &SqlitePool) -> String {
    if let Ok(Some(name)) = device_config_db::get_key(db, DEVICE_NAME_KEY).await {
        let name = name.trim();
        if !name.is_empty() {
            return name.to_string();
        }
    }
    let host = hostname::get()
        .ok()
        .and_then(|h| h.into_string().ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "this device".to_string());
    let _ = device_config_db::set_key(db, DEVICE_NAME_KEY, Some(&host)).await;
    host
}

#[cfg(test)]
mod spawn_env_tests {
    use super::WebShell;

    #[test]
    fn the_spawn_env_carries_the_whole_configuration_and_nothing_optional_when_unset() {
        let w = WebShell {
            enabled: true,
            port: 8443,
            bind: "loopback".into(),
            allow: None,
            static_dir: None,
        };
        assert_eq!(
            w.spawn_env(),
            vec![("KHTTPD_PORT", "8443".to_string()), ("KHTTPD_BIND", "loopback".to_string())]
        );

        let w = WebShell {
            enabled: true,
            port: 9000,
            bind: "127.0.0.1".into(),
            allow: Some("10.0.0.0/8".into()),
            static_dir: Some("/srv/shell".into()),
        };
        let env = w.spawn_env();
        assert!(env.contains(&("KHTTPD_PORT", "9000".to_string())));
        assert!(env.contains(&("KHTTPD_BIND", "127.0.0.1".to_string())));
        assert!(env.contains(&("KHTTPD_ALLOW", "10.0.0.0/8".to_string())));
        assert!(env.contains(&("KHTTPD_STATIC_DIR", "/srv/shell".to_string())));
    }
}
