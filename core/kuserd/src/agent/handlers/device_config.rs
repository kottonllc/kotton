// SPDX-License-Identifier: AGPL-3.0-or-later
//! Machine configuration over IPC — the machine configuring itself.
//!
//! Two authorities live apart: the user's fleet (pairing, nodes, mounts, sync
//! rules), which is `peer`'s, and **the machine's own configuration** — the
//! coordinator and TURN addresses, the QUIC gateway, the web shell and its
//! credentials, device naming, and the status reporters — which is here.
//!
//! The code draws the line itself: every function here touches
//! `device_config_db` or `web_shell_db` and **none** touches `network_db`; the
//! peer half is the exact inverse. This half stays with the daemon —
//! configuring the machine is not the fleet's authority.

use crate::agent::handlers::UserResponse;
use hex;
use kotton_device::config::db as device_config_db;
use kotton_peer::daemon::db as network_db;
use kotton_session::service::tokens as sessions;
use kotton_sys::secret::SecretsStore;
use sqlx::SqlitePool;
use std::collections::{HashMap, HashSet};
use std::io;
use std::sync::{Arc, RwLock};
use uuid::Uuid;

/// `device_config` key holding this machine's human name.
const DEVICE_NAME_KEY: &str = "device-name";

/// Set or clear the coord server URL, apply it to the running network layer, and
/// say so on the wire.
///
/// The operation is `kotton_device`'s; naming the response frame is this side's. That
/// split is the point of these wrappers — see `kotton_device::config::ops`.
///
/// The relay being left is the one the node holds reservations at now — read
/// live, since one stated for the daemon at construction was never persisted —
/// and becomes the forwarding address when the new one differs.
pub(crate) async fn coord_set(
    runtime: &Arc<kotton_device::DeviceRuntime>,
    device_db: &Arc<SqlitePool>,
    url: Option<String>,
) -> io::Result<UserResponse> {
    // The key the relay proves as it is named is recorded beside its URL, and a
    // relay re-stated is asked with the key recorded for it expected, so
    // re-stating a recorded relay is not first sight; a refusal is answered
    // before anything is written.
    let leaving = runtime.reachability().nat().relay_url;
    let key = kotton_device::config::ops::name_relay(device_db.as_ref(), Some(&leaving), url.as_deref()).await?;
    // Apply live: re-load the NAT config from the row just written and
    // reconfigure the running network layer, so the relay change takes effect
    // without a restart. Nothing but the row names a relay, so the row is the
    // answer.
    match device_config_db::load_nat_config(device_db.as_ref()).await {
        Ok(mut nat) => {
            // The key just recorded, which the row now holds too.
            nat.relay_key = key;
            if let Err(e) = runtime.reconfigure_network(nat).await {
                tracing::warn!("reconfigure_network after relay set failed: {e}");
            }
        }
        Err(e) => tracing::warn!("load_nat_config after relay set failed: {e}"),
    }
    Ok(UserResponse::RendezvousSet)
}

/// Stand this device at the relay `code` names, held to the key the code names
/// (`UserRequest::RelayStand`): a relay's line — the offer an invite's admit
/// makes, taken on the person's yes — or a relay's invite, whose *invited*
/// admission key is kept sealed in `user_id`'s store and presented there. The
/// relay proves the code's key before anything is written; the key is kept and
/// held before the network is reconfigured, so the first reservation there
/// presents it.
pub(crate) async fn relay_stand(
    runtime: &Arc<kotton_device::DeviceRuntime>,
    device_db: &Arc<SqlitePool>,
    users: &crate::residency::UserRegistry,
    user_id: &str,
    code: &str,
) -> io::Result<UserResponse> {
    use kotton_wire::line::{Code, InviteCode};
    let (url, key, invited) = match Code::parse(code).map_err(io::Error::other)? {
        Code::Line(line) if line.kind == kotton_wire::ipc::OperatedService::Relay => (line.hint, line.key, None),
        Code::Invite(InviteCode::Relay { key, hint, invited }) => (hint, key, Some(invited)),
        Code::Line(_) => {
            return Err(io::Error::other(
                "this is a vault's line: a vault is not a relay to stand at — `enrol <line>` completes the key \
                 you minted for it",
            ))
        }
        Code::Invite(InviteCode::Vault { .. }) => {
            return Err(io::Error::other(
                "this is a vault's invite: it is admitted, not stood at — `drive enrol <invite> --blind`",
            ))
        }
    };
    if url.is_empty() {
        return Err(io::Error::other("this relay's code names no address to reach it at, so nothing changed"));
    }
    stand_here(runtime, device_db, &url, key, |relay| match invited {
        None => Ok(()),
        Some(invited) => {
            let store = users
                .get(user_id)
                .ok_or_else(|| format!("user runtime '{user_id}' is not loaded"))?;
            crate::agent::operator::keep_invited(runtime, &store, relay, kotton_net::rendezvous::AdmissionKey::from_bytes(invited))
                .map_err(|e| format!("could not keep the invite's key: {e:#}"))
        }
    })
    .await
    .map_err(io::Error::other)?;
    Ok(UserResponse::RendezvousSet)
}

/// Stand this device at the relay at `url`, which must prove `key`: the row
/// written, `then` run with the relay's key (an invite's key kept and held),
/// and the running network reconfigured to it. The one way a code — a relay's
/// line or invite, or the relay an invite's admit offered — stands this device
/// anywhere; refused with nothing changed when the relay proves another key.
pub(crate) async fn stand_here(
    runtime: &Arc<kotton_device::DeviceRuntime>,
    device_db: &Arc<SqlitePool>,
    url: &str,
    key: [u8; 32],
    then: impl FnOnce(&[u8; 32]) -> Result<(), String>,
) -> Result<(), String> {
    let leaving = runtime.reachability().nat().relay_url;
    kotton_device::config::ops::stand_at(device_db.as_ref(), Some(&leaving), url, key)
        .await
        .map_err(|e| e.to_string())?;
    then(&key)?;
    match device_config_db::load_nat_config(device_db.as_ref()).await {
        Ok(nat) => {
            if let Err(e) = runtime.reconfigure_network(nat).await {
                tracing::warn!("reconfigure_network after standing at a relay failed: {e}");
            }
        }
        Err(e) => tracing::warn!("load_nat_config after standing at a relay failed: {e}"),
    }
    Ok(())
}

/// Report this machine's coord configuration.
pub(crate) async fn coord_status(device_db: &Arc<SqlitePool>) -> io::Result<UserResponse> {
    let info = kotton_device::config::ops::coord_status(device_db.as_ref()).await?;
    Ok(UserResponse::RendezvousStatus(info))
}

/// Set or clear the TURN relay URL stored in `device_config`.
pub(crate) async fn turn_set(
    device_db: &Arc<SqlitePool>,
    url: Option<String>,
) -> io::Result<UserResponse> {
    kotton_device::config::ops::set_turn_url(device_db.as_ref(), url.as_deref()).await?;
    Ok(UserResponse::TurnSet)
}

/// `device_config` key holding the one network the local door is kept open on — the
/// router's key, hashed (`kotton_peer::local_door::RouterKey`), never the Wi-Fi name.
/// Absent is the default: closed everywhere.
pub(crate) const LOCAL_DOOR_ALWAYS_KEY: &str = "local-door-always";

/// Read, or answer, the local-network door on the network this machine is on now.
///
/// *Always* is written to `device_config` as the router's key, so it survives a
/// restart; *10 minutes* is not written anywhere, so a restart closes it. The keeper
/// task moves the socket; the reading returned here says where it stands.
pub(crate) async fn local_door(
    runtime: &Arc<kotton_device::DeviceRuntime>,
    device_db: &Arc<SqlitePool>,
    answer: Option<String>,
) -> io::Result<UserResponse> {
    use kotton_peer::local_door::{network_here, DoorAnswer};
    let here = network_here();
    if let Some(word) = answer {
        let Some(answer) = DoorAnswer::parse(&word) else {
            return Ok(UserResponse::Error {
                message: format!("{word:?} is not an answer; say closed, 10m or always"),
            });
        };
        if let Err(refused) = runtime.choose_local_door(answer, here) {
            return Ok(UserResponse::Error { message: refused.to_string() });
        }
        let kept = runtime.local_door_always_router().map(|r| r.to_hex());
        device_config_db::set_key(device_db.as_ref(), LOCAL_DOOR_ALWAYS_KEY, kept.as_deref())
            .await?;
    }
    let reading = runtime.local_door_reading(tokio::time::Instant::now(), here).await;
    Ok(UserResponse::LocalDoorResult {
        answer: reading.answer.as_str().to_owned(),
        remaining_secs: reading.remaining.map(|d| d.as_secs()),
        listening: reading.listening.map(|a| a.to_string()),
        network_known: reading.network_known,
    })
}

/// Put back the network the door is kept open on, as `device_config` holds it, at
/// boot. A value that does not read as a router key keeps the door closed.
pub(crate) async fn restore_local_door(
    runtime: &kotton_device::DeviceRuntime,
    device_db: &SqlitePool,
) -> io::Result<()> {
    let kept = device_config_db::get_key(device_db, LOCAL_DOOR_ALWAYS_KEY).await?;
    runtime.restore_local_door(
        kept.as_deref().and_then(kotton_peer::local_door::RouterKey::from_hex),
    );
    Ok(())
}

/// Turn this machine's inference runtime on or off.
///
/// Takes effect at the daemon's next start, which is why it reports nothing
/// about a running process: `supervise_kinferd` is spawned at boot from this
/// key, and `kotton sidecars` is where its liveness is read.
pub(crate) async fn inference_set(
    device_db: &Arc<SqlitePool>,
    enabled: bool,
) -> io::Result<UserResponse> {
    kotton_device::config::ops::set_inference(device_db.as_ref(), enabled).await?;
    Ok(UserResponse::Ok)
}

/// Report every device-level config key as a status table.
pub(crate) async fn config_status(device_db: &Arc<SqlitePool>) -> io::Result<UserResponse> {
    let items = kotton_device::config::ops::config_items(device_db.as_ref()).await?;
    Ok(UserResponse::ConfigStatus { items })
}

/// Persist QUIC gateway configuration to `device_config`.
///
/// Fields set to `None` leave the stored value unchanged.
pub(crate) async fn quic_gateway_set(
    device_db: &Arc<SqlitePool>,
    enabled: Option<bool>,
    port: Option<u16>,
    bind: Option<String>,
    allow: Option<String>,
) -> io::Result<UserResponse> {
    kotton_device::config::ops::set_quic_gateway(device_db.as_ref(), enabled, port, bind, allow)
        .await?;
    Ok(UserResponse::Ok)
}

/// Return the current QUIC gateway configuration and expected-running status.
pub(crate) async fn quic_gateway_status(device_db: &Arc<SqlitePool>) -> io::Result<UserResponse> {
    let g = kotton_device::config::ops::quic_gateway(device_db.as_ref()).await?;
    Ok(UserResponse::QuicGatewayStatusResult {
        enabled: g.enabled,
        port: g.port,
        bind: g.bind,
        allow: g.allow,
        // `running` has always mirrored `enabled` here; the gateway's real liveness
        // is not read from config. Unchanged by the move.
        running: g.enabled,
    })
}

/// Return DID strings and raw Ed25519 public-key hex for every device paired
/// to `user_id`.  Used by `kquicd` to build its mTLS allow-list.
pub(crate) async fn get_authorized_clients(
    db: &Arc<SqlitePool>,
    user_id: String,
) -> io::Result<UserResponse> {
    // `list_paired_nodes`, not a hand-written SELECT: `paired_nodes` is peer's
    // table, and peer exposes an accessor for it.
    let nodes = network_db::list_paired_nodes(db, &user_id).await?;
    let mut dids = Vec::with_capacity(nodes.len());
    let mut pubkey_hexes = Vec::with_capacity(nodes.len());
    for node in nodes {
        dids.push(node.device_did.to_string());
        pubkey_hexes.push(hex::encode(node.public_key));
    }
    Ok(UserResponse::AuthorizedClients { dids, pubkey_hexes })
}

/// Return the 32-byte Ed25519 signing key seed for `user_id`.
///
/// `kquicd` uses these bytes to reconstruct `Ed25519DeviceCert` for the QUIC
/// mTLS server configuration.  This handler is `Local`-tier; it is
/// never reachable from a remote gateway connection.
pub(crate) async fn get_device_cert(
    user_id: &str,
    secrets: &dyn SecretsStore,
) -> io::Result<UserResponse> {
    let signing_key_bytes = kotton_device::config::ops::device_signing_key(user_id, secrets)?;
    Ok(UserResponse::DeviceCert { signing_key_bytes: kotton_wire::ipc::SecretBytes::new(signing_key_bytes) })
}

/// Enable or reconfigure `khttpd` (HTTP/WebSocket gateway sidecar).
///
/// Fields set to `None` leave the stored value unchanged.
/// `Local`-tier — gateway lifecycle is a local operator action.
pub(crate) async fn web_shell_set(
    device_db: &Arc<SqlitePool>,
    enabled: Option<bool>,
    port: Option<u16>,
    bind: Option<String>,
    static_dir: Option<String>,
    allow: Option<String>,
) -> io::Result<UserResponse> {
    kotton_device::config::ops::set_web_shell(
        device_db.as_ref(),
        enabled,
        port,
        bind,
        static_dir,
        allow,
    )
    .await?;
    Ok(UserResponse::Ok)
}

/// Return the current HTTP gateway configuration and whether `khttpd` is running.
///
/// `Local`-tier.
pub(crate) async fn web_shell_status(device_db: &Arc<SqlitePool>) -> io::Result<UserResponse> {
    let w = kotton_device::config::ops::web_shell(device_db.as_ref()).await?;
    Ok(UserResponse::WebShellStatusResult {
        enabled: w.enabled,
        port: w.port,
        bind: w.bind,
        allow: w.allow,
        static_dir: w.static_dir,
        running: w.enabled,
    })
}

/// Exchange a gateway's evidence about a third party for a session minted **for
/// that party**.
///
/// The gateway does not name the principal; it hands over what it received and
/// kuserd decides. That inversion is the whole mechanism: a gateway that could
/// name a principal could name any of them.
///
/// Only reachable from a connection whose principal is `Gateway` — enforced by
/// the caller, which is also where the mint-only rule refuses everything else a bootstrap token
/// might try.
pub(crate) async fn mint_principal_session(
    sessions: &sessions::SessionMap,
    principal_sessions: &Arc<RwLock<HashMap<String, kotton_wire::ipc::Principal>>>,
    paired_keys: &Arc<RwLock<HashSet<[u8; 32]>>>,
    user_id: String,
    evidence: kotton_wire::ipc::PrincipalEvidence,
) -> io::Result<UserResponse> {
    use kotton_wire::ipc::{Principal, PrincipalEvidence};

    let principal = match evidence {
        // kquicd asserts that *this key* completed the handshake — kuserd did not
        // observe it and cannot re-derive it (a named trust boundary).
        // What kuserd can do is check the key against the authorised set and
        // derive the DID itself, so the gateway never gets to name an identity its
        // peer's certificate does not carry.
        PrincipalEvidence::VerifiedPeerKey { pubkey_hex } => {
            let Some(pubkey) = hex::decode(&pubkey_hex)
                .ok()
                .and_then(|b| <[u8; 32]>::try_from(b).ok())
            else {
                return Ok(UserResponse::NotAllowed);
            };
            if !paired_keys.read().unwrap().contains(&pubkey) {
                tracing::warn!(
                    %pubkey_hex,
                    "MintPrincipalSession: gateway named a key that is not an authorised client"
                );
                return Ok(UserResponse::NotAllowed);
            }
            let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(&pubkey) else {
                return Ok(UserResponse::NotAllowed);
            };
            Principal::RemoteClient {
                did: kotton_crypto::did::DidKeyMethod::from_public_key(&vk).to_string(),
            }
        }
    };

    let token = Uuid::new_v4().to_string();
    sessions::insert(sessions, token.clone(), user_id.clone());
    principal_sessions
        .write()
        .unwrap()
        .insert(token.clone(), principal);

    Ok(UserResponse::PrincipalSession { token: kotton_wire::ipc::SecretText::new(token) })
}

/// Return a snapshot of all sidecar processes managed by this kuserd instance.
///
/// The kuserd row is always first (self-reported at startup). Subsequent rows
/// are written by the `supervise_*` functions in `agent/mod.rs`.
pub(crate) async fn daemon_sidecars(
    sidecar_states: &Arc<RwLock<HashMap<String, crate::agent::SidecarState>>>,
) -> io::Result<UserResponse> {
    use kotton_wire::ipc::SidecarInfo;

    // Fixed display order; unknown sidecars are appended.
    const ORDER: &[(&str, &str)] = &[
        ("kuserd", "user daemon"),
        ("ksyncd", "sync sidecar"),
        ("kquicd", "QUIC gateway"),
        ("khttpd", "HTTP gateway"),
        // Present here even when `inference.enabled` is false, because
        // the row is how a person finds out it is off: a sidecar absent from the
        // readout and absent from the machine look identical.
        ("kinferd", "inference runtime"),
    ];

    let guard = sidecar_states.read().unwrap();
    let mut sidecars: Vec<SidecarInfo> = Vec::with_capacity(4);

    for (name, role) in ORDER {
        if let Some(state) = guard.get(*name) {
            sidecars.push(SidecarInfo {
                name: name.to_string(),
                role: role.to_string(),
                enabled: state.enabled,
                running: state.running,
                pid: state.pid,
                port: state.port,
                restart_count: state.restart_count,
                started_at: state.started_at,
                failed: state.failed.clone(),
            });
        }
    }
    // Append any entries not in ORDER (forward-compat).
    for (name, state) in guard.iter() {
        if !ORDER.iter().any(|(n, _)| n == name) {
            sidecars.push(SidecarInfo {
                name: name.clone(),
                role: "sidecar".to_string(),
                enabled: state.enabled,
                running: state.running,
                pid: state.pid,
                port: state.port,
                restart_count: state.restart_count,
                started_at: state.started_at,
                failed: None,
            });
        }
    }
    drop(guard);

    Ok(UserResponse::DaemonSidecarsResult { sidecars })
}

/// Return a snapshot of all currently authenticated IPC sessions.
pub(crate) async fn ipc_sessions(
    ipc_sessions: &Arc<RwLock<HashMap<String, crate::agent::IpcSessionRecord>>>,
) -> io::Result<UserResponse> {
    use kotton_wire::ipc::IpcSessionInfo;
    use std::sync::atomic::Ordering;

    let guard = ipc_sessions.read().unwrap();
    let sessions: Vec<IpcSessionInfo> = guard
        .iter()
        .map(|(token, record)| IpcSessionInfo {
            token_prefix: token.chars().take(8).collect(),
            user_id: record.user_id.clone(),
            scope: record.scope.clone(),
            authenticated_at: record.authenticated_at,
            request_count: record.request_count.load(Ordering::Relaxed),
        })
        .collect();
    drop(guard);

    Ok(UserResponse::IpcSessionsResult { sessions })
}

/// Update the connected-peer set from a `VfsReport` message sent by ksyncd.
pub(crate) async fn vfs_report(
    connected_peers: &Arc<RwLock<HashSet<String>>>,
    peers: Vec<String>,
) -> io::Result<UserResponse> {
    let mut guard = connected_peers.write().unwrap();
    *guard = peers.into_iter().collect();
    drop(guard);
    Ok(UserResponse::Ok)
}

/// Return sync state for the given user.
pub(crate) async fn sync_status(
    _user_id: String,
    sidecar_states: &Arc<RwLock<HashMap<String, crate::agent::SidecarState>>>,
    connected_peers: &Arc<RwLock<HashSet<String>>>,
    sync_engine: &Arc<kotton_sync::engine::SyncEngine>,
) -> io::Result<UserResponse> {
    use kotton_wire::ipc::SyncStatusResult;

    let ksyncd_running = sidecar_states
        .read()
        .unwrap()
        .get("ksyncd")
        .map(|s| s.running)
        .unwrap_or(false);
    let connected_peer_count = connected_peers.read().unwrap().len() as u32;

    Ok(UserResponse::SyncStatusResult(SyncStatusResult {
        last_sync_at: sync_engine.last_sync_at(&_user_id),
        last_maintenance_at: sync_engine.last_maintenance_at(&_user_id),
        pending_changes: None,
        connected_peer_count,
        ksyncd_running,
    }))
}

/// Assemble a full network-status snapshot for the given user.
///
/// Takes both pools: paired peers are the user's (`agent.db`), gateway and
/// rendezvous configuration is the device's (`device.db`).
pub(crate) async fn network_status(
    db: &Arc<SqlitePool>,
    device_db: &Arc<SqlitePool>,
    user_id: String,
    sidecar_states: &Arc<RwLock<HashMap<String, crate::agent::SidecarState>>>,
    connected_peers: &Arc<RwLock<HashSet<String>>>,
    relay: kotton_wire::ipc::RelayReadout,
) -> io::Result<UserResponse> {
    use kotton_wire::ipc::{GatewaySummary, PeerStatus, SyncStatusResult};

    // -- Paired peers from DB ------------------------------------------------
    let nodes = network_db::list_paired_nodes(db, &user_id).await?;
    let peers_set = connected_peers.read().unwrap().clone();
    let peers: Vec<PeerStatus> = nodes
        .into_iter()
        .map(|n| PeerStatus {
            connected: peers_set.contains(&n.device_did.to_string()),
            label: n.id,
            did: n.device_did.to_string(),
            last_seen_at: None, // not tracked
        })
        .collect();

    // -- Gateway summaries ---------------------------------------------------
    let quic_enabled = device_config_db::get_key(device_db.as_ref(), "quic-gateway.enabled")
        .await?
        .map(|v| v == "true")
        .unwrap_or(false);
    let quic_port: Option<u16> = device_config_db::get_key(device_db.as_ref(), "quic-gateway.port")
        .await?
        .and_then(|v| v.parse().ok());
    let quic_bind = device_config_db::get_key(device_db.as_ref(), "quic-gateway.bind").await?;
    let quic_running = sidecar_states
        .read()
        .unwrap()
        .get("kquicd")
        .map(|s| s.running)
        .unwrap_or(false);
    let quic_gateway = GatewaySummary {
        enabled: quic_enabled,
        running: quic_running,
        port: quic_port,
        bind: quic_bind,
    };

    let http_enabled = device_config_db::get_key(device_db.as_ref(), "web-shell.enabled")
        .await?
        .map(|v| v == "true")
        .unwrap_or(false);
    let http_port: Option<u16> = device_config_db::get_key(device_db.as_ref(), "web-shell.port")
        .await?
        .and_then(|v| v.parse().ok());
    let http_bind = device_config_db::get_key(device_db.as_ref(), "web-shell.bind").await?;
    let http_running = sidecar_states
        .read()
        .unwrap()
        .get("khttpd")
        .map(|s| s.running)
        .unwrap_or(false);
    let http_gateway = GatewaySummary {
        enabled: http_enabled,
        running: http_running,
        port: http_port,
        bind: http_bind,
    };

    // -- Rendezvous URL ------------------------------------------------------
    let rendezvous_url = kotton_device::config::ops::relay_url(device_db.as_ref()).await?;

    // -- Sync state ----------------------------------------------------------
    let ksyncd_running = sidecar_states
        .read()
        .unwrap()
        .get("ksyncd")
        .map(|s| s.running)
        .unwrap_or(false);
    let connected_peer_count = peers_set.len() as u32;
    let sync = SyncStatusResult {
        last_sync_at: None,
        last_maintenance_at: None,
        pending_changes: None,
        connected_peer_count,
        ksyncd_running,
    };

    Ok(UserResponse::NetworkStatusResult {
        peers,
        quic_gateway,
        http_gateway,
        rendezvous_url,
        relay,
        sync,
    })
}

/// The relay readout alone — `ReachStatus`, the one fact of `network_status` a
/// paired browser may ask for.
pub(crate) fn reach_status(relay: kotton_wire::ipc::RelayReadout) -> UserResponse {
    UserResponse::ReachStatusResult { relay }
}

/// Resolve this device's human name — the label it announces to peers when
/// pairing. Returns the stored value, else the OS hostname (which is
/// persisted on first read, so it is stable and can then be edited).
pub(super) async fn resolve_device_name(device_db: &SqlitePool) -> String {
    kotton_device::config::ops::resolve_device_name(device_db).await
}

/// Get (`new_name = None`) or set (`Some`) this device's human name — the
/// `DeviceName` handler. Device-level; shared across users on this machine.
pub(crate) async fn device_name(
    device_db: &Arc<SqlitePool>,
    new_name: Option<String>,
) -> io::Result<UserResponse> {
    if let Some(name) = new_name {
        let name = name.trim();
        if name.is_empty() {
            return Ok(UserResponse::Error {
                message: "device name cannot be empty".to_string(),
            });
        }
        if name.chars().count() > 64 {
            return Ok(UserResponse::Error {
                message: "device name must be 64 characters or fewer".to_string(),
            });
        }
        device_config_db::set_key(device_db, DEVICE_NAME_KEY, Some(name)).await?;
        return Ok(UserResponse::DeviceNameInfo {
            name: name.to_string(),
        });
    }
    Ok(UserResponse::DeviceNameInfo {
        name: resolve_device_name(device_db).await,
    })
}

#[cfg(test)]
mod tests {
    use super::{config_status, coord_set, coord_status};
    use crate::agent::DeviceDaemon;
    use kotton_device::config::db::RelayChoice;
    use kotton_device::DeviceRuntime;
    use kotton_secret::MemorySecrets;
    use kotton_sys::ipc::IpcEndpoint;
    use kotton_wire::ipc::UserResponse;
    use sqlx::SqlitePool;
    use std::path::Path;
    use std::sync::Arc;

    /// `KOTTON_RELAY_URL` is process-wide, and the tests here that set it run
    /// in parallel. Each holds this while the variable is set, so one test's
    /// value is never what another's daemon reads.
    static RELAY_ENV: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    /// A daemon built the way every binary builds one — `RelayChoice::Configured`
    /// — at `base`, with `KOTTON_RELAY_URL` set to `env` for its construction
    /// alone. The caller holds [`RELAY_ENV`].
    async fn construct(base: &Path, env: Option<&str>) -> DeviceDaemon {
        #[cfg(unix)]
        let endpoint = IpcEndpoint::UnixSocket(base.join("kuserd.sock"));
        #[cfg(windows)]
        let endpoint = IpcEndpoint::NamedPipe(format!("kotton-test-{}", uuid::Uuid::new_v4().simple()));
        if let Some(url) = env {
            std::env::set_var("KOTTON_RELAY_URL", url);
        }
        let daemon = DeviceDaemon::new_with_base_secrets_and_relay(
            base.to_path_buf(),
            endpoint,
            Arc::new(MemorySecrets::new()),
            RelayChoice::Configured,
        )
        .await;
        std::env::remove_var("KOTTON_RELAY_URL");
        daemon.expect("construct the daemon")
    }

    /// A person who leaves their relay has none afterwards, whatever
    /// `KOTTON_RELAY_URL` holds in the daemon's process at that moment.
    ///
    /// Nothing reads the variable: a device nobody has told has no relay, and a
    /// person clearing the relay has told it, so nothing fills the row they
    /// emptied. The variable is set here only to show that it is ignored.
    #[tokio::test]
    async fn a_daemon_told_no_relay_has_none_whatever_the_environment_says() {
        let dir = tempfile::tempdir().unwrap();
        let runtime = Arc::new(
            DeviceRuntime::new_with_secrets(
                dir.path().to_path_buf(),
                kotton_device::config::RuntimeConfig::default(),
                Arc::new(MemorySecrets::new()),
            )
            .await
            .unwrap(),
        );
        let url = format!("sqlite://{}?mode=rwc", dir.path().join("device.db").display());
        let device_db = Arc::new(SqlitePool::connect(&url).await.unwrap());
        sqlx::query(
            "CREATE TABLE device_config (key TEXT PRIMARY KEY, value TEXT NOT NULL)",
        )
        .execute(device_db.as_ref())
        .await
        .unwrap();

        coord_set(&runtime, &device_db, Some("https://her-own.relay.example".into()))
            .await
            .unwrap();
        assert_eq!(
            runtime.reachability().nat().relay_url,
            "https://her-own.relay.example",
            "the relay she set is the one the daemon holds"
        );

        // Set only for the call, and removed whatever the call does.
        let env = RELAY_ENV.lock().await;
        std::env::set_var("KOTTON_RELAY_URL", "https://someone-elses.relay.example");
        let left = coord_set(&runtime, &device_db, None).await;
        std::env::remove_var("KOTTON_RELAY_URL");
        drop(env);
        left.unwrap();

        assert_eq!(
            runtime.reachability().nat().relay_url,
            "",
            "she left her relay, and the environment's is not hers to be given"
        );
    }

    /// **The desktop's daemon reads no relay from its process environment**:
    /// a device nobody has told has no relay, whatever `KOTTON_RELAY_URL` holds
    /// when it is constructed; and a person who left their relay still has none
    /// when the daemon is constructed again.
    ///
    /// Read as a deployment's default for a device nobody had told, the
    /// variable would bring back a relay the person cleared at the next start.
    #[tokio::test]
    async fn a_daemon_reads_no_relay_from_its_environment_and_one_left_stays_left() {
        let _env = RELAY_ENV.lock().await;
        let deployed = "https://the-deployments.relay.example";

        // A device nobody has told has none, with the variable set around its
        // construction.
        let untold = tempfile::tempdir().unwrap();
        let daemon = construct(untold.path(), Some(deployed)).await;
        assert_eq!(
            daemon.runtime().reachability().nat().relay_url,
            "",
            "a device nobody has told takes no relay from its environment"
        );
        drop(daemon);

        // She sets her own relay and then leaves it.
        let dir = tempfile::tempdir().unwrap();
        let daemon = construct(dir.path(), None).await;
        coord_set(
            &daemon.runtime(),
            &daemon.device_db,
            Some("https://her-own.relay.example".into()),
        )
        .await
        .unwrap();
        coord_set(&daemon.runtime(), &daemon.device_db, None)
            .await
            .unwrap();
        drop(daemon);

        // The daemon starts again on a host whose deployment names a relay.
        let daemon = construct(dir.path(), Some(deployed)).await;
        assert_eq!(
            daemon.runtime().reachability().nat().relay_url,
            "",
            "she left her relay, and a restart does not hand her the environment's"
        );

        // And what `kotton config status` and `kotton config relay` read says so.
        match config_status(&daemon.device_db).await.unwrap() {
            UserResponse::ConfigStatus { items } => {
                let relay = items
                    .iter()
                    .find(|i| i.key == "relay_url")
                    .expect("the relay row is listed");
                assert!(!relay.configured, "a cleared relay is not configured: {relay:?}");
                assert_eq!(relay.value, None);
            }
            other => panic!("config status answered {other:?}"),
        }
        match coord_status(&daemon.device_db).await.unwrap() {
            UserResponse::RendezvousStatus(info) => assert_eq!(info.url, None),
            other => panic!("relay status answered {other:?}"),
        }
    }
}
