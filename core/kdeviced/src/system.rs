// SPDX-License-Identifier: AGPL-3.0-or-later
//! `SystemDaemon` — the `kdeviced` process.
//!
//! Listens on the `kdeviced` IPC socket and manages per-user `kuserd`
//! child processes.  All device-level operations except `Ping`, `Challenge`,
//! and `Authenticate` require the caller to first prove DID ownership via the
//! challenge-response protocol defined in [`kotton_wire::sys_ipc`].

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::Signature;
use kotton_sys::ipc::IpcEndpoint;
use kotton_wire::did::Did;
use kotton_wire::{DeviceInfo, DeviceIpcSessionInfo, SysDaemonStatus, DeviceRequest, DeviceResponse, UserSessionInfo};
use kotton_crypto::DidKeyMethod;
use kotton_ipc::ChannelAcceptor;
use kotton_common::base_dir;
use kotton_common::crypto::kdf_labels;
use rand::RngCore;
use sqlx::SqlitePool;
use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tokio::process::Child;

use crate::db::operators_db;

// ── Per-connection session state ─────────────────────────────────────────────
//
// `accept_with_session` gives each connection an `Arc<Mutex<Option<DeviceSession>>>`.
// `None` is a fresh connection; the variants are the states it can reach.
//
// Article II (as amended by RFC-0063) names two principal classes at the device
// layer — an operator and a supervised child — and makes the *mechanism* uniform
// while the *authorization sets* stay separate. They are variants here, not a
// `child:`/`auth:` string prefix, so the distinction the Constitution requires is
// one the compiler checks: a handler that serves one class names its principal
// type and cannot be handed the other
// (TASK-the-device-layer-principal-classes-are-untyped). A single "authenticated"
// state would put an operator and a child on the same footing until every call
// site remembered to distinguish them — the shape RFC-0063 exists to end.

/// A DID that proved possession of a key in the device's operator set — Article II's
/// **operator**, permitted to issue any device command.
///
/// A newtype, not a bare `String`, so it cannot be passed where a [`ChildDid`] is
/// wanted or the reverse. That is the point: the principal class lives in the
/// type, and [`handle_operator_request`] / [`handle_child_request`] each name the
/// one they serve.
///
/// The child path (`handle_child_request`) requires a `&ChildDid` and the
/// operator path (`handle_operator_request`) a `&OperatorDid`, so neither can be
/// handed the other's principal. That incompatibility is exactly this, and it
/// does not build:
///
/// ```compile_fail
/// use kdeviced::system::{ChildDid, OperatorDid};
/// // Stands in for a handler that serves a supervised child.
/// fn serves_a_child(_c: &ChildDid) {}
/// // An operator principal is a different type; the compiler refuses it.
/// serves_a_child(&OperatorDid("did:key:zOperator".into()));
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperatorDid(pub String);

/// A DID that proved possession of a per-spawn ephemeral key — Article II's
/// **supervised child**, authorized only for the verbs named at its spawn.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChildDid(pub String);

/// One connection's authentication state. `None` in the slot means a fresh
/// connection; these are the states it can reach after that.
#[derive(Debug, Clone)]
pub enum DeviceSession {
    /// A `Challenge` nonce was issued; awaiting `Authenticate`.
    Challenged { nonce_b64: String },
    /// Authenticated as an operator (Article II).
    Operator(OperatorDid),
    /// Authenticated as a supervised child (Article II).
    Child(ChildDid),
}

/// The pending challenge nonce, if the connection is awaiting `Authenticate`.
fn session_nonce(session: &Mutex<Option<DeviceSession>>) -> Option<String> {
    match session.lock().ok()?.as_ref()? {
        DeviceSession::Challenged { nonce_b64 } => Some(nonce_b64.clone()),
        _ => None,
    }
}

/// The **authenticated** principal on this connection, if any.
///
/// A pending challenge is not one — the connection has been issued a nonce but
/// has proven nothing yet — so it reads back as `None`, the same as a fresh
/// connection, and neither reaches a verb handler.
fn session_principal(session: &Mutex<Option<DeviceSession>>) -> Option<DeviceSession> {
    match session.lock().ok()?.as_ref()? {
        s @ (DeviceSession::Operator(_) | DeviceSession::Child(_)) => Some(s.clone()),
        DeviceSession::Challenged { .. } => None,
    }
}

/// Replace this connection's state.
fn session_set(session: &Mutex<Option<DeviceSession>>, state: DeviceSession) {
    if let Ok(mut guard) = session.lock() {
        *guard = Some(state);
    }
}

// ── Domain types ─────────────────────────────────────────────────────────────

/// A running per-user daemon instance.
struct UserProcess {
    child: Child,
    socket_name: String,
}

/// One entry in the kctl operator session registry.
struct DeviceSessionEntry {
    did: String,
    authenticated_at: i64,
    request_count: Arc<AtomicU64>,
}

/// The system daemon.  Start with [`SystemDaemon::new`], run with
/// [`SystemDaemon::run`].
pub struct SystemDaemon {
    endpoint: IpcEndpoint,
    base: PathBuf,
    started_at: Instant,
    /// Map from user DID → running child process.
    children: Arc<RwLock<HashMap<String, UserProcess>>>,
    /// Path to the `kuserd` binary to spawn for each user.
    kuserd_bin: PathBuf,
    /// Authenticated kctl operator sessions.  Key = caller DID (one entry per
    /// authenticated connection; may linger briefly after disconnect).
    kctl_sessions: Arc<RwLock<HashMap<String, DeviceSessionEntry>>>,
    /// Supervised children and the verbs each may call — the second device
    /// principal class under Article II as amended.
    supervised_children: SupervisedChildren,
}

/// The supervised children this daemon has spawned and the verbs each may call.
///
/// In memory only, and that is the point: a child's authority begins when
/// `kdeviced` spawns it and ends when this process does. Nothing survives a
/// restart, so a credential cannot outlive the supervisor that issued it, and
/// there is no on-disk artifact for a later reader to mistake for a grant.
///
/// Key = the child's ephemeral `did:key`; value = the verbs named at its spawn.
type SupervisedChildren = Arc<RwLock<HashMap<String, Vec<String>>>>;

/// Whether `did` is a live supervised child permitted to call `verb`.
///
/// Deny is the default in both directions — an unknown DID and an unnamed verb
/// are the same refusal — so widening a child's reach requires naming the verb
/// at the spawn site, where the reason for it is visible.
fn child_may_call(children: &SupervisedChildren, did: &str, verb: &str) -> bool {
    children
        .read()
        .ok()
        .and_then(|guard| guard.get(did).map(|verbs| verbs.iter().any(|v| v == verb)))
        .unwrap_or(false)
}

/// The discriminant name of a `DeviceRequest`, for allowlist comparison.
///
/// Matches the variant name so a spawn site names verbs exactly as the protocol
/// spells them, and an allowlist entry that no longer matches a variant simply
/// stops authorizing anything rather than silently authorizing something else.
fn verb_name(request: &DeviceRequest) -> &'static str {
    match request {
        DeviceRequest::Ping => "Ping",
        DeviceRequest::Challenge => "Challenge",
        DeviceRequest::Authenticate { .. } => "Authenticate",
        DeviceRequest::GetDeviceOperationalKey => "GetDeviceOperationalKey",
        DeviceRequest::DaemonStatus => "DaemonStatus",
        DeviceRequest::StartUser { .. } => "StartUser",
        DeviceRequest::StopUser { .. } => "StopUser",
        DeviceRequest::ListSessions => "ListSessions",
        DeviceRequest::SudoersList => "SudoersList",
        DeviceRequest::SudoersAdd { .. } => "SudoersAdd",
        DeviceRequest::SudoersRemove { .. } => "SudoersRemove",
        DeviceRequest::OperatorAdd { .. } => "OperatorAdd",
        DeviceRequest::DeviceShow => "DeviceShow",
        DeviceRequest::DeviceRename { .. } => "DeviceRename",
        DeviceRequest::UserRemove { .. } => "UserRemove",
        DeviceRequest::DaemonRestart => "DaemonRestart",
        DeviceRequest::IpcSessions => "IpcSessions",
    }
}

/// The act an operator request is, and what it names — `None` for a request
/// that only reads. Every act is kept under the key that took it
/// (`operators_db::record_act`, `TASK-a-device-has-operators-not-an-operator`),
/// so nothing an operator does is anonymous among them.
fn operator_act(request: &DeviceRequest) -> Option<(&'static str, String)> {
    let subject = match request {
        DeviceRequest::StartUser { user_did }
        | DeviceRequest::StopUser { user_did }
        | DeviceRequest::UserRemove { user_did } => user_did.clone(),
        DeviceRequest::SudoersAdd { did, person } => format!("{person} {did}"),
        DeviceRequest::SudoersRemove { did } => did.clone(),
        DeviceRequest::OperatorAdd { person } => person.clone(),
        DeviceRequest::DeviceRename { name } => name.clone(),
        DeviceRequest::DaemonRestart => String::new(),
        DeviceRequest::Ping
        | DeviceRequest::Challenge
        | DeviceRequest::Authenticate { .. }
        | DeviceRequest::GetDeviceOperationalKey
        | DeviceRequest::DaemonStatus
        | DeviceRequest::ListSessions
        | DeviceRequest::SudoersList
        | DeviceRequest::DeviceShow
        | DeviceRequest::IpcSessions => return None,
    };
    Some((verb_name(request), subject))
}

/// Compute the `kuserd-{last8}` socket name for a user DID.
fn socket_name_for_did(user_did: &str) -> String {
    let short = if user_did.len() >= 8 {
        &user_did[user_did.len() - 8..]
    } else {
        user_did
    };
    format!("kuserd-{}", short)
}

/// The DIDs of every user registered on this device, read from
/// `system/users.json` — the registry the user daemons maintain.
///
/// A deliberately tolerant read (`serde_json::Value`, not the runtime's typed
/// schema): the supervisor spawns processes and holds no user machinery, so it
/// takes the two strings it needs and nothing else, and a registry field added
/// by a newer `kuserd` does not break an older `kdeviced`. A missing file is an
/// empty device; a corrupt file is logged and treated as empty rather than
/// aborting boot — the device stays administrable over IPC either way.
fn registered_user_dids(base: &Path) -> Vec<String> {
    let path = base.join("system").join("users.json");
    let contents = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Vec::new(),
        Err(e) => {
            tracing::warn!(?path, error = %e, "users registry unreadable; starting no user daemons");
            return Vec::new();
        }
    };
    let parsed: serde_json::Value = match serde_json::from_str(&contents) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(?path, error = %e, "users registry unparseable; starting no user daemons");
            return Vec::new();
        }
    };
    parsed["users"]
        .as_array()
        .map(|users| {
            users
                .iter()
                .filter_map(|u| {
                    // The DID is the spawn identity (KOTTON_USER_DID); fall back
                    // to the user id for records that predate DIDs.
                    u["did"]
                        .as_str()
                        .or_else(|| u["user_id"].as_str())
                        .map(str::to_owned)
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Spawn a `kuserd` child for `user_did` and record it in the children map.
///
/// Shared by the boot topology (one daemon per registered user, RFC-0063) and
/// the `StartUser` verb. Returns the socket name and pid; an already-running
/// user is an error only the caller can classify, so the map is checked by the
/// callers, not here.
fn spawn_user_daemon(
    children: &Arc<RwLock<HashMap<String, UserProcess>>>,
    kuserd_bin: &PathBuf,
    base: &PathBuf,
    user_did: &str,
) -> io::Result<(String, u32)> {
    let socket_name = socket_name_for_did(user_did);
    let child = tokio::process::Command::new(kuserd_bin)
        .env("KOTTON_BASE_DIR", base)
        .env("KOTTON_USER_DID", user_did)
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .spawn()
        .map_err(|e| io::Error::other(format!("failed to spawn kuserd for {user_did}: {e}")))?;

    let pid = child.id().unwrap_or(0);
    children
        .write()
        .map_err(|_| io::Error::other("lock poisoned"))?
        .insert(
            user_did.to_owned(),
            UserProcess {
                child,
                socket_name: socket_name.clone(),
            },
        );
    Ok((socket_name, pid))
}

// ── Constructor ───────────────────────────────────────────────────────────────

impl SystemDaemon {
    /// Create a new `SystemDaemon` using the default base directory and the
    /// `kuserd` binary located next to the current executable.
    pub fn new(endpoint: IpcEndpoint) -> io::Result<Self> {
        let base = base_dir().map_err(|e| io::Error::other(e.to_string()))?;

        let kuserd_bin = std::env::current_exe()?
            .parent()
            .ok_or_else(|| io::Error::other("cannot determine executable directory"))?
            .join(if cfg!(windows) {
                "kuserd.exe"
            } else {
                "kuserd"
            });

        Ok(Self {
            endpoint,
            base,
            started_at: Instant::now(),
            children: Arc::new(RwLock::new(HashMap::new())),
            kuserd_bin,
            kctl_sessions: Arc::new(RwLock::new(HashMap::new())),
            supervised_children: Arc::new(RwLock::new(HashMap::new())),
        })
    }


    /// A daemon over an explicit `base`, spawning `kuserd_bin` for each user —
    /// for an in-process caller that must not read `KOTTON_BASE_DIR`, which is
    /// process-global: a test holding a base directory of its own.
    pub fn with_base(endpoint: IpcEndpoint, base: PathBuf, kuserd_bin: PathBuf) -> Self {
        Self {
            endpoint,
            base,
            started_at: Instant::now(),
            children: Arc::new(RwLock::new(HashMap::new())),
            kuserd_bin,
            kctl_sessions: Arc::new(RwLock::new(HashMap::new())),
            supervised_children: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Run the system daemon event loop.  Blocks until the socket is closed.
    pub async fn run(self) -> io::Result<()> {
        // Open (or create) the device database.
        let db_path = self.base.join("system").join("device.db");
        let device_db = Arc::new(
            operators_db::open(&db_path)
                .await
                .map_err(|e| io::Error::other(format!("device db init: {e}")))?,
        );
        // A key carried over from the `sudoers` list that is itself an
        // account's DID answers for that account.
        operators_db::bind_own_keys(&device_db, &registered_user_dids(&self.base)).await?;

        let server = ChannelAcceptor::<DeviceRequest, DeviceResponse>::listen(self.endpoint.clone()).await?;
        println!("kdeviced listening on {:?}", self.endpoint);

        // ── Boot topology (RFC-0063 stage 2) ─────────────────────────────────
        // One kuserd per registered user, spawned with KOTTON_USER_DID so each
        // loads exactly its principal (stage 1). Failures warn rather than
        // abort: a device with a broken user is still administrable, and
        // `StartUser` can retry any of these by hand.
        for user_did in registered_user_dids(&self.base) {
            match spawn_user_daemon(&self.children, &self.kuserd_bin, &self.base, &user_did) {
                Ok((socket_name, pid)) => {
                    tracing::info!(user = %user_did, socket = %socket_name, pid, "user daemon started");
                    operators_db::log_device_event(
                        &device_db,
                        "lifecycle",
                        "user daemon started at boot",
                        Some(&format!("{{\"user_did\":\"{user_did}\",\"pid\":{pid}}}")),
                    )
                    .await;
                }
                Err(e) => {
                    tracing::warn!(user = %user_did, error = %e, "user daemon failed to start");
                    operators_db::log_device_event(
                        &device_db,
                        "lifecycle",
                        "user daemon failed to start at boot",
                        Some(&format!("{{\"user_did\":\"{user_did}\"}}")),
                    )
                    .await;
                }
            }
        }

        let started_at = self.started_at;
        let children = Arc::clone(&self.children);
        let base = self.base.clone();
        let kuserd_bin = self.kuserd_bin.clone();
        let version = kotton_version::VERSION.to_string();
        let kctl_sessions = Arc::clone(&self.kctl_sessions);
        let supervised_children = Arc::clone(&self.supervised_children);

        server
            .accept_with_session(move |request, _caller, session| {
                let children = Arc::clone(&children);
                let base = base.clone();
                let kuserd_bin = kuserd_bin.clone();
                let version = version.clone();
                let device_db = Arc::clone(&device_db);
                let kctl_sessions = Arc::clone(&kctl_sessions);
                let supervised_children = Arc::clone(&supervised_children);
                async move {
                    handle_sys_request(
                        request,
                        session,
                        started_at,
                        &children,
                        &base,
                        &kuserd_bin,
                        &version,
                        &device_db,
                        &kctl_sessions,
                        &supervised_children,
                    )
                    .await
                }
            })
            .await
    }
}

// ── Supervised-child requests ─────────────────────────────────────────────────

/// Serve a verb a supervised child is authorized for.
///
/// Separate from the operator handler on purpose: the two principal classes get
/// two code paths, so a verb cannot become reachable to a child by being added
/// to the operator's `match`. Authorization is already checked by the caller;
/// this function only serves.
async fn handle_child_request(
    _child: &ChildDid,
    request: DeviceRequest,
    base: &Path,
) -> io::Result<DeviceResponse> {
    match request {
        DeviceRequest::GetDeviceOperationalKey => {
            let secrets = kotton_secret::secrets_for_base_dir(base)
                .map_err(|e| io::Error::other(format!("secrets store open failed: {e}")))?;
            let hex_key = secrets
                .get_secret(&kdf_labels::device_operational_key())
                .map_err(|e| io::Error::other(format!("keychain read failed: {e}")))?;
            let Some(hex_key) = hex_key else {
                return Ok(DeviceResponse::Error {
                    message: "device operational key not found".into(),
                });
            };
            let bytes = hex::decode(&hex_key)
                .map_err(|e| io::Error::other(format!("invalid operational key hex: {e}")))?;
            if bytes.len() != 32 {
                return Ok(DeviceResponse::Error {
                    message: "operational key must be 32 bytes".into(),
                });
            }
            Ok(DeviceResponse::DeviceOperationalKey {
                signing_key_bytes: kotton_wire::ipc::SecretBytes::new(bytes),
            })
        }

        // Authorization ran before this call, so anything else here means a verb
        // was named at a spawn site without a handler to serve it.
        other => Ok(DeviceResponse::Error {
            message: format!(
                "{} is not served on the supervised-child path",
                verb_name(&other)
            ),
        }),
    }
}

/// The context an operator handler needs — the daemon's shared state, bundled so
/// the typed handler takes one argument rather than a long list.
struct OperatorCtx<'a> {
    started_at: Instant,
    children: &'a Arc<RwLock<HashMap<String, UserProcess>>>,
    base: &'a PathBuf,
    kuserd_bin: &'a PathBuf,
    version: &'a str,
    device_db: &'a SqlitePool,
    kctl_sessions: &'a Arc<RwLock<HashMap<String, DeviceSessionEntry>>>,
}

/// Serve a verb for an authenticated **operator** (Article II).
///
/// Requires an [`OperatorDid`], so a supervised child — which holds a [`ChildDid`]
/// — cannot reach this path: the boundary the Constitution names is one the
/// compiler checks (TASK-the-device-layer-principal-classes-are-untyped). The
/// child's verbs live in [`handle_child_request`], which requires the other type.
async fn handle_operator_request(
    op: &OperatorDid,
    other: DeviceRequest,
    ctx: OperatorCtx<'_>,
) -> io::Result<DeviceResponse> {
    let OperatorCtx {
        started_at,
        children,
        base,
        kuserd_bin,
        version,
        device_db,
        kctl_sessions,
    } = ctx;
    let caller_did = op.0.clone();
    // Count this request against the operator's session.
    {
        if let Ok(guard) = kctl_sessions.read() {
            if let Some(entry) = guard.get(&caller_did) {
                entry.request_count.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
                match other {
                DeviceRequest::DaemonStatus => {
                    let count = children
                        .read()
                        .map_err(|_| io::Error::other("lock poisoned"))?
                        .len();
                    Ok(DeviceResponse::DaemonStatus(SysDaemonStatus {
                        uptime_secs: started_at.elapsed().as_secs(),
                        active_user_count: count,
                        version: version.to_string(),
                    }))
                }

                DeviceRequest::ListSessions => {
                    let guard = children
                        .read()
                        .map_err(|_| io::Error::other("lock poisoned"))?;
                    let sessions = guard
                        .iter()
                        .map(|(did, proc)| UserSessionInfo {
                            user_did: did.clone(),
                            socket_name: proc.socket_name.clone(),
                            pid: proc.child.id().unwrap_or(0),
                        })
                        .collect();
                    Ok(DeviceResponse::SessionList { sessions })
                }

                DeviceRequest::StartUser { user_did } => {
                    {
                        let guard = children
                            .read()
                            .map_err(|_| io::Error::other("lock poisoned"))?;
                        if let Some(proc) = guard.get(&user_did) {
                            return Ok(DeviceResponse::UserAlreadyRunning {
                                socket_name: proc.socket_name.clone(),
                                pid: proc.child.id().unwrap_or(0),
                            });
                        }
                    }

                    let (socket_name, pid) =
                        spawn_user_daemon(children, kuserd_bin, base, &user_did)?;
                    operators_db::log_device_event(
                        device_db,
                        "lifecycle",
                        "user daemon started",
                        Some(&format!("{{\"user_did\":\"{user_did}\",\"pid\":{pid}}}")),
                    )
                    .await;

                    Ok(DeviceResponse::UserStarted {
                        user_did,
                        socket_name,
                        pid,
                    })
                }

                DeviceRequest::StopUser { user_did } => {
                    let maybe_proc = {
                        let mut guard = children
                            .write()
                            .map_err(|_| io::Error::other("lock poisoned"))?;
                        guard.remove(&user_did)
                    };
                    let Some(mut proc) = maybe_proc else {
                        return Ok(DeviceResponse::UserNotRunning);
                    };
                    let _ = proc.child.kill().await;
                    operators_db::log_device_event(
                        device_db,
                        "lifecycle",
                        "user daemon stopped",
                        Some(&format!("{{\"user_did\":\"{user_did}\"}}")),
                    )
                    .await;
                    Ok(DeviceResponse::UserStopped { user_did })
                }

                DeviceRequest::SudoersList => {
                    let operators = operators_db::list(device_db).await?;
                    Ok(DeviceResponse::SudoersList { operators })
                }

                // Any operator adds one, from the people with an account here.
                DeviceRequest::SudoersAdd { did: new_did, person } => {
                    // The credential is a key the new operator can prove by
                    // signing a nonce; anything else would be a row nobody can
                    // ever authenticate as — or a name standing for a key.
                    let is_key = new_did
                        .parse::<Did>()
                        .ok()
                        .is_some_and(|d| DidKeyMethod::to_public_key(&d).is_ok());
                    if !is_key {
                        return Ok(DeviceResponse::Error {
                            message: format!(
                                "{new_did} is not a key — an operator's credential is a did:key they sign with"
                            ),
                        });
                    }
                    let accounts = registered_user_dids(base);
                    match operators_db::add(device_db, &new_did, &person, &caller_did, &accounts).await? {
                        Ok(()) => Ok(DeviceResponse::SudoersModified),
                        Err(refused) => Ok(DeviceResponse::Error {
                            message: refused.to_string(),
                        }),
                    }
                }

                // Any operator makes a person an operator, by the key their own
                // daemon proved and kept for them — never a key the caller names.
                DeviceRequest::OperatorAdd { person } => {
                    let accounts = registered_user_dids(base);
                    match operators_db::take_kept_key(device_db, &person, &caller_did, &accounts).await? {
                        Ok(_) => Ok(DeviceResponse::SudoersModified),
                        Err(refused) => Ok(DeviceResponse::Error {
                            message: refused.to_string(),
                        }),
                    }
                }

                // Any operator steps one down — themselves included — except
                // the last, which nobody can.
                DeviceRequest::SudoersRemove { did: remove_did } => {
                    match operators_db::remove(device_db, &remove_did).await? {
                        Ok(removed) => {
                            tracing::info!(removed = ?removed, by = %caller_did, "operator stepped down");
                            Ok(DeviceResponse::SudoersModified)
                        }
                        Err(refused) => Ok(DeviceResponse::Error {
                            message: refused.to_string(),
                        }),
                    }
                }

                DeviceRequest::DeviceShow => {
                    let name = operators_db::get_device_name(device_db).await?;
                    Ok(DeviceResponse::DeviceInfo(DeviceInfo { did: None, name }))
                }

                DeviceRequest::DeviceRename { name } => {
                    operators_db::set_device_name(device_db, &name).await?;
                    Ok(DeviceResponse::Ok)
                }

                DeviceRequest::UserRemove { user_did } => {
                    // An operator is one of the people with an account here, so
                    // taking an operator's account off the device would leave a
                    // key answering for nobody. Stepping them down is its own
                    // act, and the last operator's never happens.
                    if operators_db::is_operator_person(device_db, &user_did).await? {
                        return Ok(DeviceResponse::Error {
                            message: format!(
                                "{user_did} is one of this device's operators — step them down first"
                            ),
                        });
                    }
                    // 1. Kill the running daemon if there is one.
                    let maybe_proc = {
                        let mut guard = children
                            .write()
                            .map_err(|_| io::Error::other("lock poisoned"))?;
                        guard.remove(&user_did)
                    };
                    if let Some(mut proc) = maybe_proc {
                        let _ = proc.child.kill().await;
                    }

                    // 2. Wipe the user's local cache directory.
                    let user_cache = base.join("users").join(&user_did);
                    if user_cache.exists() {
                        tokio::fs::remove_dir_all(&user_cache).await.ok();
                    }

                    Ok(DeviceResponse::UserRemovedAndWiped { user_did })
                }

                DeviceRequest::DaemonRestart => {
                    // Respond first, then exit after a brief delay so the
                    // response has time to flush.  A supervisor (or the user)
                    // is responsible for restarting kdeviced.
                    tokio::spawn(async {
                        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
                        std::process::exit(0);
                    });
                    Ok(DeviceResponse::Ok)
                }

                DeviceRequest::IpcSessions => {
                    let guard = kctl_sessions
                        .read()
                        .map_err(|_| io::Error::other("lock poisoned"))?;
                    let sessions = guard
                        .values()
                        .map(|e| DeviceIpcSessionInfo {
                            did: e.did.clone(),
                            authenticated_at: e.authenticated_at,
                            request_count: e.request_count.load(Ordering::Relaxed),
                        })
                        .collect();
                    drop(guard);
                    Ok(DeviceResponse::IpcSessionsResult { sessions })
                }

                // Child-only, and an operator has no use for it: the fewer
                // principals that can name a durable machine identity, the
                // better. Refused rather than served, so that reaching it
                // requires being a supervised child rather than merely being
                // authenticated.
                DeviceRequest::GetDeviceOperationalKey => Ok(DeviceResponse::Error {
                    message: "GetDeviceOperationalKey is authorized for supervised children only"
                        .into(),
                }),

                // These were handled above and cannot reach this branch.
                DeviceRequest::Ping | DeviceRequest::Challenge | DeviceRequest::Authenticate { .. } => {
                    unreachable!("handled before the auth gate")
                }
            }
}

// ── Request handler ───────────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
async fn handle_sys_request(
    request: DeviceRequest,
    session: Arc<Mutex<Option<DeviceSession>>>,
    started_at: Instant,
    children: &Arc<RwLock<HashMap<String, UserProcess>>>,
    base: &PathBuf,
    kuserd_bin: &PathBuf,
    version: &str,
    device_db: &SqlitePool,
    kctl_sessions: &Arc<RwLock<HashMap<String, DeviceSessionEntry>>>,
    supervised_children: &SupervisedChildren,
) -> io::Result<DeviceResponse> {
    match request {
        // ── Unauthenticated ───────────────────────────────────────────────────
        DeviceRequest::Ping => Ok(DeviceResponse::Pong),

        DeviceRequest::Challenge => {
            let mut nonce_bytes = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
            let nonce_b64 = URL_SAFE_NO_PAD.encode(nonce_bytes);
            session_set(&session, DeviceSession::Challenged { nonce_b64: nonce_b64.clone() });
            Ok(DeviceResponse::ChallengeIssued { nonce: nonce_b64 })
        }

        DeviceRequest::Authenticate {
            did,
            nonce,
            signature,
            person,
        } => {
            // 1. Retrieve the nonce issued to this connection.
            let Some(stored_nonce_b64) = session_nonce(&session) else {
                return Ok(DeviceResponse::AuthFailed {
                    reason: "no Challenge issued on this connection".into(),
                });
            };

            // 2. The caller must echo back the exact nonce string we issued.
            if nonce != stored_nonce_b64 {
                return Ok(DeviceResponse::AuthFailed {
                    reason: "nonce mismatch".into(),
                });
            }

            // 3. Decode raw nonce bytes for signature verification.
            let nonce_raw = match URL_SAFE_NO_PAD.decode(&nonce) {
                Ok(b) => b,
                Err(_) => {
                    return Ok(DeviceResponse::AuthFailed {
                        reason: "invalid nonce encoding".into(),
                    })
                }
            };

            // 4. Decode the signature (must be exactly 64 bytes).
            let sig_bytes = match URL_SAFE_NO_PAD.decode(&signature) {
                Ok(b) if b.len() == 64 => b,
                _ => {
                    return Ok(DeviceResponse::AuthFailed {
                        reason: "signature must be 64 base64url-encoded bytes".into(),
                    })
                }
            };
            let sig_arr: [u8; 64] = sig_bytes.try_into().unwrap();
            let ed_sig = Signature::from_bytes(&sig_arr);

            // 5. Extract the Ed25519 verifying key from the did:key DID.
            let did_typed: Did = match did.parse() {
                Ok(d) => d,
                Err(e) => {
                    return Ok(DeviceResponse::AuthFailed {
                        reason: format!("invalid DID: {e}"),
                    })
                }
            };
            let verifying_key = match DidKeyMethod::to_public_key(&did_typed) {
                Ok(vk) => vk,
                Err(e) => {
                    return Ok(DeviceResponse::AuthFailed {
                        reason: format!("cannot extract key from DID: {e}"),
                    })
                }
            };

            // 6. Verify the Ed25519 signature over the raw nonce bytes.
            if verifying_key.verify_strict(&nonce_raw, &ed_sig).is_err() {
                return Ok(DeviceResponse::AuthFailed {
                    reason: "signature verification failed".into(),
                });
            }

            // 7a. A live supervised child authenticates as itself, never as an
            // operator. Checked *before* the operator set because the two are
            // disjoint by construction and a child must never fall through to
            // the bootstrap enrolment below — on a device whose operator set is
            // still empty, that fallthrough would promote a spawned process to
            // the first operator of the machine.
            if supervised_children
                .read()
                .ok()
                .map(|guard| guard.contains_key(&did))
                .unwrap_or(false)
            {
                session_set(&session, DeviceSession::Child(ChildDid(did.clone())));
                return Ok(DeviceResponse::Authenticated { did });
            }

            // 7b. Check the operator set; auto-enroll the first verified DID
            // on a device that has none — in one statement, so two first
            // callers cannot both become the first operator.
            //
            // A person's own daemon names the person its key is theirs for
            // (`person`). On an empty device that binds the first key at once;
            // otherwise a key that is not an operator's is **kept** as theirs
            // and admits nothing — the connection stays unauthenticated, and an
            // operator makes the person an operator with `OperatorAdd`, naming
            // them and never a key
            // (`TASK-this-devices-operators-box-speaks-to-kdeviced-under-the-persons-own-key`).
            if !operators_db::is_operator(device_db, &did).await? {
                let accounts = registered_user_dids(base);
                let first_as = person.as_deref().filter(|p| accounts.iter().any(|a| a == p));
                if operators_db::bootstrap(device_db, &did, first_as).await? {
                    if person.is_some() && first_as.is_none() {
                        tracing::warn!("the first operator's key was enrolled and answers for nobody yet: the person it named has no account");
                    }
                } else {
                    let Some(person) = person else {
                        return Ok(DeviceResponse::AuthFailed {
                            reason: "DID is not one of this device's operators".into(),
                        });
                    };
                    let refused = match operators_db::keep_own_key(device_db, &did, &person, &accounts).await? {
                        operators_db::Kept::Kept => return Ok(DeviceResponse::OperatorKeyKept { person }),
                        // A proof of this same key on another connection
                        // enrolled it between the reads above: then it stands,
                        // and this connection authenticates below.
                        operators_db::Kept::Operator => None,
                        operators_db::Kept::NoAccount => Some(format!("{person} has no account on this device")),
                        operators_db::Kept::AnotherKey => {
                            Some(format!("another key is already kept as {person}'s own on this device"))
                        }
                        operators_db::Kept::Taken => Some("this key is already someone else's on this device".into()),
                    };
                    if let Some(reason) = refused {
                        return Ok(DeviceResponse::AuthFailed { reason });
                    }
                }
            }

            // 8. Commit authenticated state; consume the pending nonce.
            session_set(&session, DeviceSession::Operator(OperatorDid(did.clone())));

            // 9. Register this operator session in the kctl_sessions map.
            let now_secs = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;
            {
                let entry = DeviceSessionEntry {
                    did: did.clone(),
                    authenticated_at: now_secs,
                    request_count: Arc::new(AtomicU64::new(0)),
                };
                kctl_sessions
                    .write()
                    .unwrap()
                    .insert(did.clone(), entry);
            }

            Ok(DeviceResponse::Authenticated { did })
        }

        // ── Authenticated ─────────────────────────────────────────────────────
        //
        // The principal class is a type now (Article II), so the two paths are
        // two typed handlers and the compiler keeps a child off the operator's
        // (TASK-the-device-layer-principal-classes-are-untyped).
        other => match session_principal(&session) {
            Some(DeviceSession::Child(child)) => {
                // A supervised child reaches only the verbs named at its spawn;
                // `handle_child_request` requires a `&ChildDid`, so a verb added
                // to the operator handler cannot become reachable to it.
                let verb = verb_name(&other);
                if !child_may_call(supervised_children, &child.0, verb) {
                    return Ok(DeviceResponse::Error {
                        message: format!("supervised child is not authorized for {verb}"),
                    });
                }
                handle_child_request(&child, other, base).await
            }
            Some(DeviceSession::Operator(op)) => {
                // Standing is the key's row, read again on every request: an
                // operator stepped down on another connection is refused here,
                // on the next act of a connection they already hold, and the
                // connection is theirs no longer.
                if !operators_db::is_operator(device_db, &op.0).await? {
                    if let Ok(mut guard) = session.lock() {
                        *guard = None;
                    }
                    if let Ok(mut sessions) = kctl_sessions.write() {
                        sessions.remove(&op.0);
                    }
                    return Ok(DeviceResponse::Error {
                        message: format!("{} is no longer one of this device's operators", op.0),
                    });
                }
                let act = operator_act(&other);
                let answer = handle_operator_request(
                    &op,
                    other,
                    OperatorCtx {
                        started_at,
                        children,
                        base,
                        kuserd_bin,
                        version,
                        device_db,
                        kctl_sessions,
                    },
                )
                .await;
                // Every act is kept under the key that took it; one that
                // cannot be kept is answered as an error rather than as done.
                if let Some((act, subject)) = act {
                    let ok = matches!(&answer, Ok(r) if !matches!(r, DeviceResponse::Error { .. }));
                    if let Err(e) = operators_db::record_act(device_db, &op.0, act, &subject, ok).await {
                        tracing::error!(error = %e, act, "an operator's act could not be kept");
                        return Ok(DeviceResponse::Error {
                            message: format!("{act} ran but could not be kept under the key that took it: {e}"),
                        });
                    }
                }
                answer
            }
            // A pending challenge (nonce issued, not yet authenticated), or a
            // fresh connection: not authorized for any verb below.
            _ => Ok(DeviceResponse::Unauthenticated),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn write_registry(base: &std::path::Path, json: &str) {
        let system = base.join("system");
        std::fs::create_dir_all(&system).unwrap();
        std::fs::write(system.join("users.json"), json).unwrap();
    }

    // ── The supervised-child principal class (RFC-0063 stage 4 item 1) ───────

    fn registry_with(did: &str, verbs: &[&str]) -> SupervisedChildren {
        let map: HashMap<String, Vec<String>> = std::iter::once((
            did.to_string(),
            verbs.iter().map(|v| v.to_string()).collect(),
        ))
        .collect();
        Arc::new(RwLock::new(map))
    }

    /// The session slot carries the principal as a type, not a `child:`/`auth:`
    /// string: each state round-trips, and the two authenticated classes are
    /// distinct variants (TASK-the-device-layer-principal-classes-are-untyped).
    #[test]
    fn the_session_slot_carries_a_typed_principal() {
        let slot: Mutex<Option<DeviceSession>> = Mutex::new(None);
        // Fresh: no nonce, no principal.
        assert!(session_nonce(&slot).is_none());
        assert!(session_principal(&slot).is_none());
        // A challenge is a state, read back as its nonce and nothing else.
        session_set(&slot, DeviceSession::Challenged { nonce_b64: "abc".into() });
        assert_eq!(session_nonce(&slot).as_deref(), Some("abc"));
        assert!(session_principal(&slot).is_none(), "a challenge is not a principal");
        // An operator and a child are different variants.
        session_set(&slot, DeviceSession::Operator(OperatorDid("did:key:zOp".into())));
        assert!(matches!(session_principal(&slot), Some(DeviceSession::Operator(_))));
        assert!(session_nonce(&slot).is_none(), "an operator has no pending nonce");
        session_set(&slot, DeviceSession::Child(ChildDid("did:key:zChild".into())));
        assert!(matches!(session_principal(&slot), Some(DeviceSession::Child(_))));
    }

    /// A child reaches the verb named at its spawn.
    #[test]
    fn child_reaches_the_verb_named_at_spawn() {
        let reg = registry_with("did:key:zChild", &["GetDeviceOperationalKey"]);
        assert!(child_may_call(&reg, "did:key:zChild", "GetDeviceOperationalKey"));
    }

    /// …and nothing else. This is the property that keeps a supervised child
    /// from being an operator: `StartUser` and `SudoersAdd` are the authority
    /// RFC-0063 disqualified an accept loop from holding.
    #[test]
    fn child_reaches_nothing_it_was_not_given() {
        let reg = registry_with("did:key:zChild", &["GetDeviceOperationalKey"]);
        for verb in ["StartUser", "SudoersAdd", "DaemonRestart", "UserRemove"] {
            assert!(
                !child_may_call(&reg, "did:key:zChild", verb),
                "{verb} must not be reachable by a supervised child"
            );
        }
    }

    /// A DID that is not a live child is refused even for the verb a child
    /// would be allowed — the registry is the whole authority, and it is
    /// in-memory, so a stale credential from a previous supervisor is nobody.
    #[test]
    fn unknown_did_is_not_a_child() {
        let reg = registry_with("did:key:zChild", &["GetDeviceOperationalKey"]);
        assert!(!child_may_call(&reg, "did:key:zStranger", "GetDeviceOperationalKey"));
    }

    /// An empty registry authorizes nothing. Stated separately because it is
    /// the state every `kdeviced` starts in, and a permissive empty case would
    /// be invisible until something was spawned.
    #[test]
    fn empty_registry_authorizes_nothing() {
        let reg: SupervisedChildren = Arc::new(RwLock::new(HashMap::new()));
        assert!(!child_may_call(&reg, "did:key:zChild", "GetDeviceOperationalKey"));
    }

    /// `verb_name` must agree with the protocol spelling, or an allowlist entry
    /// silently stops matching. Pinned for the two verbs the split turns on.
    #[test]
    fn verb_names_match_the_protocol() {
        assert_eq!(
            verb_name(&DeviceRequest::GetDeviceOperationalKey),
            "GetDeviceOperationalKey"
        );
        assert_eq!(
            verb_name(&DeviceRequest::StartUser {
                user_did: "did:key:z1".into()
            }),
            "StartUser"
        );
    }

    /// A device with no registry is an empty device, not an error.
    #[test]
    fn no_registry_means_no_user_daemons() {
        let temp = TempDir::new().unwrap();
        assert!(registered_user_dids(temp.path()).is_empty());
    }

    /// The boot topology (RFC-0063 stage 2): every registered user gets a
    /// daemon, identified by the DID `kdeviced` will spawn with.
    #[test]
    fn every_registered_user_is_a_spawn_target() {
        let temp = TempDir::new().unwrap();
        write_registry(
            temp.path(),
            r#"{"users":[
                {"user_id":"alice","did":"did:kel:aaaa1111"},
                {"user_id":"bob","did":"did:kel:bbbb2222"}
            ]}"#,
        );

        let dids = registered_user_dids(temp.path());
        assert_eq!(dids, vec!["did:kel:aaaa1111", "did:kel:bbbb2222"]);
    }

    /// A record that predates DIDs still starts — by its user id, which the
    /// stage-1 principal matcher also accepts.
    #[test]
    fn a_pre_did_record_falls_back_to_its_user_id() {
        let temp = TempDir::new().unwrap();
        write_registry(temp.path(), r#"{"users":[{"user_id":"alice"}]}"#);

        assert_eq!(
            registered_user_dids(temp.path()),
            vec!["alice"]
        );
    }

    /// A corrupt registry must not take the supervisor down with it — the
    /// device stays administrable over IPC, and `StartUser` still works.
    #[test]
    fn a_corrupt_registry_starts_nothing_and_kills_nothing() {
        let temp = TempDir::new().unwrap();
        write_registry(temp.path(), "not json at all");

        assert!(registered_user_dids(temp.path()).is_empty());
    }

    /// A registry field this supervisor has never heard of is ignored, not
    /// fatal — a newer kuserd may write fields an older kdeviced cannot know.
    #[test]
    fn unknown_registry_fields_are_tolerated() {
        let temp = TempDir::new().unwrap();
        write_registry(
            temp.path(),
            r#"{"users":[{"user_id":"alice","did":"did:kel:aaaa1111","from_the_future":{"x":1}}],"registry_version":99}"#,
        );

        assert_eq!(
            registered_user_dids(temp.path()),
            vec!["did:kel:aaaa1111"]
        );
    }

    // ── A device has operators, not an operator ──────────────────────────────
    //
    // TASK-a-device-has-operators-not-an-operator. Every request below goes
    // through `handle_sys_request`, the function the socket's acceptor calls
    // for each frame — the door, with the socket's framing taken off — on a
    // connection slot of its own, as a second kctl on the same machine has.

    /// One device: a base directory with accounts in its registry, its
    /// `device.db`, and the maps the daemon keeps.
    struct Device {
        base: TempDir,
        db: SqlitePool,
        children: Arc<RwLock<HashMap<String, UserProcess>>>,
        kctl_sessions: Arc<RwLock<HashMap<String, DeviceSessionEntry>>>,
        supervised: SupervisedChildren,
    }

    /// A person: an account on the device, and the key they operate with.
    struct Person {
        key: ed25519_dalek::SigningKey,
        did: String,
    }

    fn person() -> Person {
        let key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let did = DidKeyMethod::from_public_key(&key.verifying_key()).to_string();
        Person { key, did }
    }

    type Conn = Arc<Mutex<Option<DeviceSession>>>;

    async fn device_with(accounts: &[&Person]) -> Device {
        let base = TempDir::new().unwrap();
        let users: Vec<String> = accounts
            .iter()
            .map(|p| format!("{{\"user_id\":\"u{}\",\"did\":\"{}\"}}", &p.did[p.did.len() - 6..], p.did))
            .collect();
        write_registry(base.path(), &format!("{{\"users\":[{}]}}", users.join(",")));
        let db = operators_db::open(&base.path().join("system").join("device.db")).await.unwrap();
        Device {
            base,
            db,
            children: Arc::new(RwLock::new(HashMap::new())),
            kctl_sessions: Arc::new(RwLock::new(HashMap::new())),
            supervised: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    impl Device {
        async fn say(&self, conn: &Conn, request: DeviceRequest) -> DeviceResponse {
            handle_sys_request(
                request,
                Arc::clone(conn),
                Instant::now(),
                &self.children,
                &self.base.path().to_path_buf(),
                &PathBuf::from("/nonexistent/kuserd"),
                "test",
                &self.db,
                &self.kctl_sessions,
                &self.supervised,
            )
            .await
            .expect("the door answers")
        }

        /// A fresh connection, authenticated as `who` by signing its nonce.
        async fn connect(&self, who: &Person) -> (Conn, DeviceResponse) {
            self.connect_for(who, None).await
        }

        /// A fresh connection on which `key` signs its nonce, said to be the
        /// own key of `person` when that is `Some` — as a person's daemon
        /// speaks with the key it keeps in their sealed store.
        async fn connect_for(&self, who: &Person, person: Option<&Person>) -> (Conn, DeviceResponse) {
            let conn: Conn = Arc::new(Mutex::new(None));
            let DeviceResponse::ChallengeIssued { nonce } = self.say(&conn, DeviceRequest::Challenge).await else {
                panic!("no challenge");
            };
            let raw = URL_SAFE_NO_PAD.decode(&nonce).unwrap();
            use ed25519_dalek::Signer as _;
            let signature = URL_SAFE_NO_PAD.encode(who.key.sign(&raw).to_bytes());
            let answer = self
                .say(
                    &conn,
                    DeviceRequest::Authenticate {
                        did: who.did.clone(),
                        nonce,
                        signature,
                        person: person.map(|p| p.did.clone()),
                    },
                )
                .await;
            (conn, answer)
        }

        async fn operator(&self, who: &Person) -> Conn {
            let (conn, answer) = self.connect(who).await;
            assert!(
                matches!(answer, DeviceResponse::Authenticated { .. }),
                "{} did not authenticate as an operator: {answer:?}",
                who.did
            );
            conn
        }

        async fn add(&self, conn: &Conn, who: &Person) -> DeviceResponse {
            self.say(
                conn,
                DeviceRequest::SudoersAdd {
                    did: who.did.clone(),
                    person: who.did.clone(),
                },
            )
            .await
        }
    }

    /// The first person on a device enrols on first contact and binds their
    /// key to their own account, as `kctl user create` does.
    async fn first_operator(device: &Device, who: &Person) -> Conn {
        let conn = device.operator(who).await;
        assert!(matches!(device.add(&conn, who).await, DeviceResponse::SudoersModified));
        conn
    }

    fn refused(answer: DeviceResponse) -> String {
        match answer {
            DeviceResponse::Error { message } => message,
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    /// **Two operators each add a person, and the device records which did
    /// which.** Ana is the first operator and makes Ben one; then Ana adds
    /// Cai and Ben adds Dee, each on their own connection with their own key.
    /// The set holds four keys, each answering for its own person, and the
    /// acts are kept under the key that took each — Ana's twice, Ben's once.
    #[tokio::test]
    async fn two_operators_each_add_a_person_and_the_device_records_which_did_which() {
        let (ana, ben, cai, dee) = (person(), person(), person(), person());
        let device = device_with(&[&ana, &ben, &cai, &dee]).await;
        let at_ana = first_operator(&device, &ana).await;
        assert!(matches!(device.add(&at_ana, &ben).await, DeviceResponse::SudoersModified));
        let at_ben = device.operator(&ben).await;

        assert!(matches!(device.add(&at_ana, &cai).await, DeviceResponse::SudoersModified));
        assert!(matches!(device.add(&at_ben, &dee).await, DeviceResponse::SudoersModified));

        let DeviceResponse::SudoersList { operators } = device.say(&at_ben, DeviceRequest::SudoersList).await else {
            panic!("no list");
        };
        let whose = |p: &Person| operators.iter().find(|o| o.did == p.did).map(|o| (o.person.clone(), o.added_by.clone()));
        assert_eq!(whose(&ana), Some((Some(ana.did.clone()), "bootstrap".to_string())));
        assert_eq!(whose(&ben), Some((Some(ben.did.clone()), ana.did.clone())));
        assert_eq!(whose(&cai), Some((Some(cai.did.clone()), ana.did.clone())), "Ana added Cai");
        assert_eq!(whose(&dee), Some((Some(dee.did.clone()), ben.did.clone())), "Ben added Dee");

        let acts = operators_db::acts(&device.db).await.unwrap();
        let by = |p: &Person| -> Vec<String> {
            acts.iter()
                .filter(|a| a.did == p.did && a.act == "SudoersAdd" && a.ok)
                .map(|a| a.subject.clone())
                .collect()
        };
        assert_eq!(
            by(&ana),
            vec![
                format!("{} {}", ana.did, ana.did),
                format!("{} {}", ben.did, ben.did),
                format!("{} {}", cai.did, cai.did)
            ],
            "Ana's acts are kept under Ana's key: {acts:?}"
        );
        assert_eq!(by(&ben), vec![format!("{} {}", dee.did, dee.did)], "Ben's under Ben's: {acts:?}");
        // A read is not an act, and is not kept.
        assert!(acts.iter().all(|a| a.act != "SudoersList"), "{acts:?}");
    }

    /// **An operator is one of the people with an account here, holding a
    /// key of their own.** A person with no account is refused; a key already
    /// someone's is refused for anyone else; the refusals are kept too.
    #[tokio::test]
    async fn an_operator_is_a_person_with_an_account_and_a_key_is_never_shared() {
        let (ana, ben, stranger) = (person(), person(), person());
        let device = device_with(&[&ana, &ben]).await;
        let at_ana = first_operator(&device, &ana).await;

        let no_account = refused(device.add(&at_ana, &stranger).await);
        assert!(no_account.contains("has no account on this device"), "{no_account}");

        // An account's DID names a person and signs nothing: it is never a key.
        let not_a_key = refused(
            device
                .say(
                    &at_ana,
                    DeviceRequest::SudoersAdd {
                        did: "did:kel:EBen".into(),
                        person: ben.did.clone(),
                    },
                )
                .await,
        );
        assert!(not_a_key.contains("is not a key"), "{not_a_key}");

        // Ana's key, offered as Ben's.
        let shared = refused(
            device
                .say(
                    &at_ana,
                    DeviceRequest::SudoersAdd {
                        did: ana.did.clone(),
                        person: ben.did.clone(),
                    },
                )
                .await,
        );
        assert!(shared.contains("never shared"), "{shared}");
        let operators = operators_db::list(&device.db).await.unwrap();
        assert_eq!(operators.len(), 1, "nothing was added: {operators:?}");
        assert_eq!(operators[0].person.as_deref(), Some(ana.did.as_str()));

        let acts = operators_db::acts(&device.db).await.unwrap();
        assert_eq!(acts.iter().filter(|a| a.act == "SudoersAdd" && !a.ok).count(), 3, "{acts:?}");
    }

    /// **An operator removes the other, and is refused when they are the
    /// last.** Ana makes Ben an operator and steps him down; then she tries to
    /// step herself down and is refused — a device always has one — and she
    /// is still its operator. Handing the device on is add-then-step-down:
    /// Ana adds Ben again, and he steps her down.
    #[tokio::test]
    async fn an_operator_removes_the_other_and_is_refused_when_they_are_the_last() {
        let (ana, ben) = (person(), person());
        let device = device_with(&[&ana, &ben]).await;
        let at_ana = first_operator(&device, &ana).await;
        assert!(matches!(device.add(&at_ana, &ben).await, DeviceResponse::SudoersModified));

        let remove = |who: &Person| DeviceRequest::SudoersRemove { did: who.did.clone() };
        assert!(matches!(device.say(&at_ana, remove(&ben)).await, DeviceResponse::SudoersModified));
        assert!(!operators_db::is_operator(&device.db, &ben.did).await.unwrap());

        let last = refused(device.say(&at_ana, remove(&ana)).await);
        assert!(last.contains("last operator"), "{last}");
        assert!(operators_db::is_operator(&device.db, &ana.did).await.unwrap(), "the last stays");

        // Handing it on.
        assert!(matches!(device.add(&at_ana, &ben).await, DeviceResponse::SudoersModified));
        let at_ben = device.operator(&ben).await;
        assert!(matches!(device.say(&at_ben, remove(&ana)).await, DeviceResponse::SudoersModified));
        let left: Vec<String> = operators_db::list(&device.db).await.unwrap().into_iter().map(|o| o.did).collect();
        assert_eq!(left, vec![ben.did.clone()]);
        let last = refused(device.say(&at_ben, remove(&ben)).await);
        assert!(last.contains("last operator"), "{last}");

        // Every step-down, and every refusal, kept under the key that said it.
        let acts = operators_db::acts(&device.db).await.unwrap();
        let removals: Vec<(&str, &str, bool)> = acts
            .iter()
            .filter(|a| a.act == "SudoersRemove")
            .map(|a| (a.did.as_str(), a.subject.as_str(), a.ok))
            .collect();
        assert_eq!(
            removals,
            vec![
                (ana.did.as_str(), ben.did.as_str(), true),
                (ana.did.as_str(), ana.did.as_str(), false),
                (ben.did.as_str(), ana.did.as_str(), true),
                (ben.did.as_str(), ben.did.as_str(), false),
            ]
        );
    }

    /// Stepping a person down takes every key of theirs — here the machine's
    /// first-run key bound to Ana, and her identity's own — and is refused
    /// when those keys are all the device has.
    #[tokio::test]
    async fn stepping_a_person_down_takes_every_key_of_theirs() {
        let (ana, machine, ben) = (person(), person(), person());
        let device = device_with(&[&ana, &ben]).await;
        let at_machine = device.operator(&machine).await;
        // `kctl user create` for the first person: her identity's key, and the
        // machine key bound to her.
        assert!(matches!(device.add(&at_machine, &ana).await, DeviceResponse::SudoersModified));
        assert!(matches!(
            device
                .say(&at_machine, DeviceRequest::SudoersAdd { did: machine.did.clone(), person: ana.did.clone() })
                .await,
            DeviceResponse::SudoersModified
        ));
        let last = refused(device.say(&at_machine, DeviceRequest::SudoersRemove { did: ana.did.clone() }).await);
        assert!(last.contains("last operator"), "{last}");
        assert_eq!(operators_db::list(&device.db).await.unwrap().len(), 2, "both of Ana's keys stay");

        assert!(matches!(device.add(&at_machine, &ben).await, DeviceResponse::SudoersModified));
        assert!(matches!(
            device.say(&at_machine, DeviceRequest::SudoersRemove { did: ana.did.clone() }).await,
            DeviceResponse::SudoersModified
        ));
        let left: Vec<String> = operators_db::list(&device.db).await.unwrap().into_iter().map(|o| o.did).collect();
        assert_eq!(left, vec![ben.did.clone()], "both of Ana's keys went");
    }

    /// Two operators stepping each other down at the same moment cannot
    /// both succeed: the guard is in the one statement that deletes.
    #[tokio::test]
    async fn two_operators_stepping_each_other_down_at_once_leave_one() {
        for _ in 0..20 {
            let (ana, ben) = (person(), person());
            let device = device_with(&[&ana, &ben]).await;
            let at_ana = first_operator(&device, &ana).await;
            assert!(matches!(device.add(&at_ana, &ben).await, DeviceResponse::SudoersModified));
            let (a, b) = tokio::join!(
                operators_db::remove(&device.db, &ben.did),
                operators_db::remove(&device.db, &ana.did)
            );
            let done = [a.unwrap(), b.unwrap()].iter().filter(|r| r.is_ok()).count();
            assert_eq!(done, 1, "exactly one step-down lands");
            assert_eq!(operators_db::list(&device.db).await.unwrap().len(), 1, "a device always has one");
        }
    }

    /// **A revoked operator's next act is refused at the door.** Ben holds a
    /// connection he authenticated on while he was an operator. Ana steps him
    /// down on hers. Ben's very next request on the connection he already
    /// holds is refused — standing is his key's row, read per request — and
    /// the connection is his no longer; a fresh proof of his key is refused
    /// too, so no act of his reaches the device after the removal.
    #[tokio::test]
    async fn a_revoked_operators_next_act_is_refused_at_the_door() {
        let (ana, ben, cai) = (person(), person(), person());
        let device = device_with(&[&ana, &ben, &cai]).await;
        let at_ana = first_operator(&device, &ana).await;
        assert!(matches!(device.add(&at_ana, &ben).await, DeviceResponse::SudoersModified));
        let at_ben = device.operator(&ben).await;
        assert!(matches!(
            device.say(&at_ben, DeviceRequest::SudoersList).await,
            DeviceResponse::SudoersList { .. }
        ));

        assert!(matches!(
            device.say(&at_ana, DeviceRequest::SudoersRemove { did: ben.did.clone() }).await,
            DeviceResponse::SudoersModified
        ));

        // The next act on the connection Ben already holds.
        let next = refused(device.add(&at_ben, &cai).await);
        assert!(next.contains("no longer one of this device's operators"), "{next}");
        assert!(!operators_db::is_operator(&device.db, &cai.did).await.unwrap(), "Ben's act did not land");
        // And the one after: the connection is unauthenticated now.
        assert!(matches!(
            device.say(&at_ben, DeviceRequest::SudoersList).await,
            DeviceResponse::Unauthenticated
        ));
        // A fresh proof of the same key.
        let (_, again) = device.connect(&ben).await;
        assert!(matches!(again, DeviceResponse::AuthFailed { .. }), "{again:?}");
        // Nothing of Ben's after the removal was kept as an act.
        let acts = operators_db::acts(&device.db).await.unwrap();
        assert!(
            acts.iter().filter(|a| a.did == ben.did).count() == 0,
            "a refused-at-the-door request is not an act of Ben's: {acts:?}"
        );
    }

    /// Taking an operator's account off the device would leave a key
    /// answering for nobody, so it is refused until they are stepped down.
    #[tokio::test]
    async fn an_operators_account_is_not_removed_while_they_operate() {
        let (ana, ben) = (person(), person());
        let device = device_with(&[&ana, &ben]).await;
        let at_ana = first_operator(&device, &ana).await;
        assert!(matches!(device.add(&at_ana, &ben).await, DeviceResponse::SudoersModified));
        let refusal = refused(device.say(&at_ana, DeviceRequest::UserRemove { user_did: ben.did.clone() }).await);
        assert!(refusal.contains("step them down first"), "{refusal}");
        assert!(matches!(
            device.say(&at_ana, DeviceRequest::SudoersRemove { did: ben.did.clone() }).await,
            DeviceResponse::SudoersModified
        ));
        assert!(matches!(
            device.say(&at_ana, DeviceRequest::UserRemove { user_did: ben.did.clone() }).await,
            DeviceResponse::UserRemovedAndWiped { .. }
        ));
    }

    /// First run enrols one key, however many callers race for it.
    #[tokio::test]
    async fn two_first_callers_enrol_one_operator() {
        let (ana, ben) = (person(), person());
        let device = device_with(&[&ana, &ben]).await;
        let (a, b) = tokio::join!(
            operators_db::bootstrap(&device.db, &ana.did, None),
            operators_db::bootstrap(&device.db, &ben.did, None)
        );
        assert_eq!([a.unwrap(), b.unwrap()].iter().filter(|x| **x).count(), 1);
        assert_eq!(operators_db::list(&device.db).await.unwrap().len(), 1);
    }

    /// A device whose `device.db` predates operators keeps its `sudoers`
    /// keys as operators; a key is bound to the first account its holder
    /// created (the `did:kel` row it added), and a key that is itself an
    /// account's DID to that account when kdeviced opens it. A `did:kel` row — an account's
    /// DID as `kctl user create` used to add it, which nobody could ever
    /// authenticate as — is not carried, so it cannot stand in for "not the
    /// last".
    #[tokio::test]
    async fn a_sudoers_list_from_before_is_carried_into_the_operator_set() {
        let (ana, machine) = (person(), person());
        let base = TempDir::new().unwrap();
        let path = base.path().join("device.db");
        let url = format!("sqlite://{}?mode=rwc", path.display());
        {
            let pool = SqlitePool::connect(&url).await.unwrap();
            // The three migrations before this one, as they are in the tree.
            for sql in [
                include_str!("../migrations/0001_init.sql"),
                include_str!("../migrations/0002_device_config.sql"),
                include_str!("../migrations/0003_device_events.sql"),
            ] {
                sqlx::raw_sql(sql).execute(&pool).await.unwrap();
            }
            // The machine's key, a legacy account whose DID is its own key,
            // and an account's `did:kel` as `kctl user create` used to add it.
            // `kctl user create`, run under the machine key, added the first
            // account's did:kel with `added_by` that key — and a second
            // account's later.
            for (did, at, by) in [
                (machine.did.as_str(), 1, "bootstrap"),
                (ana.did.as_str(), 1, "bootstrap"),
                ("did:kel:EFirst", 2, machine.did.as_str()),
                ("did:kel:ESecond", 3, machine.did.as_str()),
            ] {
                sqlx::query("INSERT INTO sudoers (did, added_at, added_by) VALUES (?, ?, ?)")
                    .bind(did)
                    .bind(at)
                    .bind(by)
                    .execute(&pool)
                    .await
                    .unwrap();
            }
            pool.close().await;
        }
        // Stand in for sqlx's own bookkeeping of the three applied above, so
        // the migrator runs only the fourth.
        let migrator = sqlx::migrate!("./migrations");
        {
            let pool = SqlitePool::connect(&url).await.unwrap();
            sqlx::raw_sql(
                "CREATE TABLE _sqlx_migrations (version BIGINT PRIMARY KEY, description TEXT NOT NULL, \
                 installed_on TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, success BOOLEAN NOT NULL, \
                 checksum BLOB NOT NULL, execution_time BIGINT NOT NULL)",
            )
            .execute(&pool)
            .await
            .unwrap();
            for m in migrator.iter().filter(|m| m.version < 4) {
                sqlx::query(
                    "INSERT INTO _sqlx_migrations (version, description, success, checksum, execution_time) \
                     VALUES (?, ?, 1, ?, 0)",
                )
                .bind(m.version)
                .bind(&*m.description)
                .bind(&*m.checksum)
                .execute(&pool)
                .await
                .unwrap();
            }
            pool.close().await;
        }
        let db = operators_db::open(&path).await.unwrap();
        operators_db::bind_own_keys(&db, std::slice::from_ref(&ana.did)).await.unwrap();
        let operators = operators_db::list(&db).await.unwrap();
        assert_eq!(operators.len(), 2, "only keys are carried — the did:kel row signs nothing: {operators:?}");
        let person_of = |did: &str| operators.iter().find(|o| o.did == did).and_then(|o| o.person.clone());
        assert_eq!(person_of(&ana.did), Some(ana.did.clone()), "ana's own key answers for her");
        assert_eq!(
            person_of(&machine.did).as_deref(),
            Some("did:kel:EFirst"),
            "the machine key answers for the first account its holder created, not the second"
        );
        // So the next `kctl user create` finds a person already bound and does
        // not take the next account for the first.
        assert!(operators.iter().any(|o| o.person.is_some()));
        let old: Option<(String,)> =
            sqlx::query_as("SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'sudoers'")
                .fetch_optional(&db)
                .await
                .unwrap();
        assert!(old.is_none(), "the old list is gone");
    }

    // ── Each person's own key (the pane's half) ──────────────────────────────
    //
    // TASK-this-devices-operators-box-speaks-to-kdeviced-under-the-persons-own-key.
    // A person is an account (`ana.did` stands for it, as in the tests above);
    // their own key is a second key their daemon minted into their store.

    /// **An operator makes a person an operator by naming the person, and the
    /// key is the one that person's own daemon proved.** Ben's daemon proves
    /// his own key: it is kept as his and stands for nothing — the connection
    /// is not authenticated. Ana names Ben (`OperatorAdd`), never a key; Ben's
    /// key now authenticates, answers for Ben, and was added by Ana's key; and
    /// the act is kept under Ana's key. Deleting the `person` binding in
    /// `keep_own_key`'s insert, or taking the key from anywhere but what was
    /// kept, turns this red.
    #[tokio::test]
    async fn a_persons_own_key_is_kept_and_stands_for_nothing_until_an_operator_names_them() {
        let (ana, ben, cai) = (person(), person(), person());
        let (ben_key, other_key) = (person(), person());
        let device = device_with(&[&ana, &ben, &cai]).await;
        let at_ana = first_operator(&device, &ana).await;

        // Cai's daemon has kept nothing: naming Cai makes nobody an operator.
        let refused_cai = refused(device.say(&at_ana, DeviceRequest::OperatorAdd { person: cai.did.clone() }).await);
        assert!(refused_cai.contains("no key of their own"), "{refused_cai}");

        let (at_ben, kept) = device.connect_for(&ben_key, Some(&ben)).await;
        assert!(matches!(&kept, DeviceResponse::OperatorKeyKept { person } if *person == ben.did), "{kept:?}");
        assert!(
            matches!(device.say(&at_ben, DeviceRequest::SudoersList).await, DeviceResponse::Unauthenticated),
            "a kept key stands for nothing"
        );
        // Proving it again changes nothing; a second, different key for Ben is refused.
        let (_, again) = device.connect_for(&ben_key, Some(&ben)).await;
        assert!(matches!(again, DeviceResponse::OperatorKeyKept { .. }), "{again:?}");
        let (_, second) = device.connect_for(&other_key, Some(&ben)).await;
        assert!(matches!(&second, DeviceResponse::AuthFailed { reason } if reason.contains("another key")), "{second:?}");
        // And a key cannot be kept for someone with no account.
        let stranger = person();
        let (_, nobody) = device.connect_for(&other_key, Some(&stranger)).await;
        assert!(matches!(&nobody, DeviceResponse::AuthFailed { reason } if reason.contains("no account")), "{nobody:?}");

        assert!(matches!(
            device.say(&at_ana, DeviceRequest::OperatorAdd { person: ben.did.clone() }).await,
            DeviceResponse::SudoersModified
        ));
        let at_ben = device.operator(&ben_key).await;
        let DeviceResponse::SudoersList { operators } = device.say(&at_ben, DeviceRequest::SudoersList).await else {
            panic!("no list");
        };
        let row = operators.iter().find(|o| o.did == ben_key.did).expect("Ben's own key is an operator's");
        assert_eq!(row.person.as_deref(), Some(ben.did.as_str()), "it answers for Ben");
        assert_eq!(row.added_by, ana.did, "Ana's key added it");
        assert!(operators.iter().all(|o| o.did != other_key.did), "the refused key stands nowhere: {operators:?}");

        let acts = operators_db::acts(&device.db).await.unwrap();
        assert!(
            acts.iter().any(|a| a.did == ana.did && a.act == "OperatorAdd" && a.subject == ben.did && a.ok),
            "the add is kept under Ana's key: {acts:?}"
        );
        assert!(
            acts.iter().any(|a| a.did == ana.did && a.act == "OperatorAdd" && a.subject == cai.did && !a.ok),
            "and so is the refused one: {acts:?}"
        );
    }

    /// **On an empty device the first person's own key is theirs at once.**
    /// Trust on first use, as before (DEC-0017), but bound to the person the
    /// daemon speaks for rather than to nobody.
    #[tokio::test]
    async fn the_first_persons_own_key_on_an_empty_device_answers_for_them() {
        let (ana, ana_key) = (person(), person());
        let device = device_with(&[&ana]).await;
        let (conn, answer) = device.connect_for(&ana_key, Some(&ana)).await;
        assert!(matches!(answer, DeviceResponse::Authenticated { .. }), "{answer:?}");
        let DeviceResponse::SudoersList { operators } = device.say(&conn, DeviceRequest::SudoersList).await else {
            panic!("no list");
        };
        assert_eq!(operators.len(), 1);
        assert_eq!(operators[0].did, ana_key.did);
        assert_eq!(operators[0].person.as_deref(), Some(ana.did.as_str()));
    }
}
