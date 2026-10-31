// SPDX-License-Identifier: AGPL-3.0-or-later
use crate::bundled::bundled_apps;
use crate::event_log::SqliteEventLog;
use crate::infer_proxy::InferProxy;
use crate::surface_proxy::SurfaceProxy;
use crate::device_users::UserId;
use handlers::CallerContext;
use kotton_app::daemon::db::app_registry_db;
use kotton_common::base_dir;
use kotton_device::config::db::RelayChoice;
use kotton_device::config::RuntimeConfig;
use kotton_device::users::DeviceUsers as _;
use kotton_device::DeviceRuntime;
use kotton_diag::service::spawn_subscriber_task;
use kotton_diag::service::EventScope;
use kotton_ipc::{ChannelAcceptor, HandlerOutput};
use kotton_peer::PeerHandler;
use kotton_schemas::AppManifest;
use kotton_session::service::tokens as sessions;
use kotton_sys::ipc::IpcEndpoint;
use kotton_sys::secret::SecretsStore;
use sqlx::SqlitePool;
use std::collections::{HashMap, HashSet};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::Instant;
use tokio::task::JoinHandle;

mod app_host;
mod browser_channel;
mod ceremony;
mod joining;
mod compositor;
mod device_operator;
pub mod custody_window;
mod dispatch;
mod file_host;
mod peer_reach;
mod handlers;
mod infer_host;
mod liveness;
mod mailbox;
mod message_host;
mod org_roots;
pub(crate) mod network_readout;
/// **`pub` so the suite can drive an unlock through the host the guest calls.**
/// The interface the desktop's lock screen uses is `auth.unlock-with-pin`, and
/// `DaemonOccupantHost` is the only implementation of it; a test that drove
/// anything else would be testing a second answer to the same question. Nothing
/// here is authority a caller did not already hold — the struct is a bundle of
/// borrows of a `DeviceDaemon`'s own state, and only a caller with that state
/// can build one.
pub mod occupant_host;
mod door;
mod operator;
pub use operator::commands_the_copy_tells_a_person_to_type;
mod protocol;
mod outbox_keeper;
mod outbox_shelf;
mod reach_keeper;
mod read_mark_host;
mod record_access;
mod sealed_read;
mod sidecar_token;
mod streamed;
mod vault_doors;
pub use protocol::{UserRequest, UserResponse};
use kotton_wire::ipc::PeerRequest;
pub use vault_doors::doors_for;

/// Per-connection session state stored by the IPC server's session slot.
///
/// Replaces the bare `Option<String>` token so that the connection's scope
/// allow-list can be stored alongside the token.
///
/// Not `Clone`: it now carries the live browser channel, which owns one
/// ceremony's ephemeral secret and must not be duplicated. Nothing cloned it.
struct ConnSessionData {
    /// The session token bound to this connection.
    token: String,
    /// Optional allow-list of `UserRequest` variant names.  `None` or empty
    /// means full access (the default for CLI and Tauri host connections).
    scope: Option<Vec<String>>,
    /// Whether this node has a CEK available for the authenticated user.
    ///
    /// `false` on blind relay nodes (paired via `PairingPayload::BlindRelay`);
    /// any request requiring decryption returns `UserResponse::Error` with a
    /// message starting with `"NoCek:"`.  Set at `Authenticate` time by
    /// checking whether `seed32` is present in the OS keychain.
    cek_available: bool,
    /// The connection's trust origin, bound here at `Authenticate` from the credential
    /// kuserd issued, by way of `Principal::trust_origin` — a gateway or an mTLS
    /// peer is `Remote`, a browser admitted by ceremony is `Paired`,
    /// a direct local client is `Local`.
    /// The dispatch floor enforces `origin >= required_trust(req)`.
    origin: kotton_wire::ConnTrustOrigin,
    /// **Whose** authority this connection carries.
    ///
    /// Bound here at `Authenticate` from the credential, exactly as `origin` is,
    /// and never settable by the caller. A gateway acting for a third party
    /// authenticates with a token kuserd minted *for that party*, so handlers can
    /// ask who is calling instead of seeing only the sidecar.
    principal: kotton_wire::ipc::Principal,
    /// The sealed browser channel this connection is carrying, if any.
    ///
    /// The name of this connection's browser channel, when the gateway did not
    /// give one.
    ///
    /// The channel itself lives in the node's registry, because two connections
    /// reach it — one carrying calls in, one carrying frames out. A gateway
    /// that names its channel needs nothing here. One that does not gets a name
    /// minted on its first frame and remembered for the connection's life, so
    /// two browsers on two connections are two channels rather than one they
    /// both corrupt.
    browser_key: Option<String>,
}

impl ConnSessionData {
    /// The session a browser's inner request is dispatched under: a `Browser`
    /// principal at `Paired` origin, so it faces the ordinary floor
    /// and scope. Origin is read off the principal rather than passed in, so
    /// this mint site cannot disagree with `Authenticate`'s.
    fn browser_session(token: String, cek_available: bool, credential_id: String) -> Self {
        let principal = kotton_wire::ipc::Principal::Browser { credential_id };
        Self {
            origin: principal.trust_origin(),
            token,
            scope: None,
            cek_available,
            principal,
            browser_key: None,
        }
    }
}

// -- Runtime inspection state -----------------------------------------------

/// Live state of a sidecar process supervised by kuserd.
///
/// `pub` rather than `pub(crate)`: `supervise_kinferd` takes the map, and the
/// integration suite runs that supervisor rather than a copy of it. Every field
/// here already crosses the wire as `SidecarInfo`, so
/// this widens no fact — only who may name the struct carrying it.
#[derive(Debug, Clone)]
pub struct SidecarState {
    /// **The last thing that went wrong, and why** — not a live state.
    /// `running` says whether a process is up now; this says what the last
    /// ending was, and it outlives a restart on purpose.
    ///
    /// It carries the terminal case — a process that never ran past its first
    /// moments, reported here once instead of restarted forever — and the
    /// ordinary failure too: a sidecar that exited non-zero and is being
    /// restarted. Without the second, `kotton sidecars` would show a rising
    /// `restart_count` and no cause, and a sidecar that refused a frame would
    /// look exactly like one that had been asked to stop. A restart is not a
    /// reason to forget what happened; supervision that ends in silence is the
    /// half-design this field closes.
    pub failed: Option<String>,
    pub enabled: bool,
    pub running: bool,
    /// OS PID of the current process, if running.
    pub pid: Option<u32>,
    /// Listening port, if known from config.
    pub port: Option<u16>,
    /// Number of times the supervisor has restarted this process.
    pub restart_count: u32,
    /// Unix timestamp (seconds) of the most recent successful spawn.
    pub started_at: Option<i64>,
}

/// Per-connection session record for `IpcSessions` introspection.
pub(crate) struct IpcSessionRecord {
    pub user_id: String,
    pub scope: Option<Vec<String>>,
    pub authenticated_at: i64,
    pub request_count: Arc<std::sync::atomic::AtomicU64>,
}

/// System daemon  wraps DeviceRuntime and routes IPC requests
/// The daemon's shared state, as one value.
///
/// **It exists because clippy counted to 22.** `handle_request` took
/// twenty-two arguments, and they were not an argument list — they were
/// `DeviceDaemon`'s fields, splatted. The same list appeared three times: cloned
/// out of `self`, cloned again per connection, then passed positionally. A
/// signature that size is not a lint problem; it is a type that has not been
/// named yet, and this is the type.
///
/// Every field is an `Arc` or equally cheap to clone, which is what makes one
/// value per connection the same cost as twenty-two were.
///
/// It is also where the user-runtime registry lives: the registry is the
/// daemon's bookkeeping of lifetimes the daemon owns, and "the daemon's shared
/// state" is exactly this struct. The
/// design decision and the lint turned out to be naming the same absence.
#[derive(Clone)]
pub(super) struct AgentContext {
    pub(super) runtime: Arc<DeviceRuntime>,
    /// Where this daemon listens — what a sidecar it spawns is told to dial.
    pub(super) endpoint: IpcEndpoint,
    /// Which users are resident in this daemon.
    ///
    /// The daemon's, not the machine's: this is bookkeeping of
    /// lifetimes the daemon creates and ends, and `device` keeps only
    /// fingerprint -> user_id. Cloneable and `Arc`-backed, so every holder sees
    /// the same registry rather than a snapshot.
    pub(super) users: crate::residency::UserRegistry,
    /// The same per-user seam the sync engine holds — `users` and `record_stores`
    /// behind one trait, so `file_host` can be built without naming either. Both
    /// remain above because other arms still resolve residency directly.
    pub(super) sync_resources: Arc<dyn kotton_sync::SyncHost>,
    /// Which record stores are open in this daemon.
    ///
    /// The second residency map, held by the daemon and not by `DeviceRuntime`.
    /// A cache of open per-user stores is a path to user data, and the machine
    /// handle lives in `core/device`, which states that nothing in it may reach
    /// any.
    pub(super) record_stores: crate::residency::RecordStores,
    pub(super) db: Arc<SqlitePool>,
    pub(super) device_db: Arc<SqlitePool>,
    pub(super) user_dbs: crate::db::user_db::UserDbMap,
    pub(super) event_log_tasks: crate::event_log::EventLogTasks,
    pub(super) base: PathBuf,
    pub(super) started_at: Instant,
    pub(super) sessions: sessions::SessionMap,
    pub(super) gateway_tokens: Arc<RwLock<HashSet<String>>>,
    pub(super) principal_sessions: Arc<RwLock<HashMap<String, kotton_wire::ipc::Principal>>>,
    pub(super) paired_keys: Arc<RwLock<HashSet<[u8; 32]>>>,
    pub(super) sync_engine: Arc<kotton_sync::engine::SyncEngine>,
    pub(super) live_instances:
        Arc<tokio::sync::Mutex<HashMap<String, kotton_app::daemon::apps::LongLivedInstance>>>,
    pub(super) revoked_sessions: Arc<RwLock<HashSet<String>>>,
    pub(super) pending_confirms: kotton_peer::daemon::nodes::PendingConfirms,
    pub(super) browser_desks: browser_channel::BrowserDesks,
    pub(super) browser_channels: browser_channel::BrowserChannels,
    /// Contact ceremonies in flight, and what a running one needs to reach the
    /// shell. Held here because a ceremony outlives the
    /// host call that starts it — see `agent::ceremony`.
    pub(super) ceremonies: ceremony::Ceremonies,
    pub(super) sidecar_states: Arc<RwLock<HashMap<String, SidecarState>>>,
    pub(super) ipc_sessions: Arc<RwLock<HashMap<String, IpcSessionRecord>>>,
    pub(super) connected_peers: Arc<RwLock<HashSet<String>>>,
    pub(super) surface_proxy: Arc<SurfaceProxy>,
    /// The inference channel, for the verbs that reach it.
    ///
    /// A handle nothing reads would be a claim the channel is wired to a verb,
    /// and this one is read: `interface infer` reaches the daemon through
    /// `RunnerHostCall::Infer`, and `DaemonInferHost` is what answers it.
    pub(super) infer_proxy: Arc<InferProxy>,
    /// Which app windows are open, per owner. The daemon's, not the device
    /// runtime's: a window is a thing the surface domain has, and a runtime
    /// carrying one would make a vault link `surface`, which a vault does not.
    pub(super) window_registry: Arc<dyn kotton_surface::WindowRegistry>,
    pub(super) file_reassembly: kotton_device::users::files::SealedReassembly,
    /// The binary that runs an app. See [`DeviceDaemon::runner`].
    pub(super) runner: PathBuf,
}

/// Who a daemon serves and who supervises it: the one person it is
/// for, and where their machine's `kdeviced` listens. See
/// [`DeviceDaemon::new_supervised`].
#[derive(Debug, Clone, Default)]
pub struct Supervision {
    /// The person's DID (or user id), as `kdeviced` names them at spawn.
    pub principal: Option<String>,
    /// `kdeviced`'s socket; `None` is the machine's own.
    pub kdeviced: Option<IpcEndpoint>,
}

pub struct DeviceDaemon {
    runtime: Arc<DeviceRuntime>,
    /// Which users are resident in this daemon. See [`AgentContext::users`].
    users: crate::residency::UserRegistry,
    /// Which record stores are open. See [`AgentContext::record_stores`].
    record_stores: crate::residency::RecordStores,
    endpoint: IpcEndpoint,
    db: Arc<SqlitePool>,
    /// The device-scope database (`system/device.db`, owned by kdeviced).
    /// `device_config` reads and the interim config writes go here — never to
    /// `agent.db`.
    device_db: Arc<SqlitePool>,
    /// Per-user agent databases (`users/{id}/agent.db`), opened lazily and
    /// encrypted from the user's master secret.
    user_dbs: crate::db::user_db::UserDbMap,
    /// Live per-user event-log tasks. Held so logout can stop a user's log
    /// before closing the pool that log writes through.
    event_log_tasks: crate::event_log::EventLogTasks,
    /// The device log's task. Held for the same reason the per-user handles are:
    /// it owns a clone of `db`, so shutdown has to stop it before closing that
    /// pool, or the log writes into a closed one.
    device_log_task: std::sync::Mutex<Option<JoinHandle<()>>>,
    /// **Stop serving.** Notified when the person quits Kotton: quitting stops
    /// the daemon, and closing the window does not.
    ///
    /// It does not tear anything down and it does not end the process. All it
    /// does is end [`Self::serve`], which returns to [`Self::run`] — the one
    /// place that owns the teardown — so quitting and a failed listener leave
    /// through the same door. A second shutdown path is the thing this field is
    /// shaped to avoid: `shutdown` is ordered, innermost holder first, and a
    /// caller that ended the process itself would skip every step of it.
    quit: Arc<tokio::sync::watch::Sender<bool>>,
    /// The base directory for all daemon-managed files (agent.db, apps/, etc.).
    base: PathBuf,
    /// When the daemon process started (used to compute uptime for `DaemonStatus`).
    started_at: Instant,
    /// Active session tokens — maps token string to the session it names.
    ///
    /// A token is inserted when `CreateUser` or `LoginWithRecoveryKey` succeeds
    /// and removed when `LockSession` is called, the connection drops, or the
    /// session expires. Resolve one through [`sessions::live_user`] rather than
    /// indexing the map, so expiry is applied on every lookup.
    sessions: sessions::SessionMap,
    /// Bootstrap tokens minted for **gateway** sidecars (kquicd / khttpd). A session
    /// authenticating with one of these is `Remote`; every other token is
    /// `Local`. Gateways cannot self-elevate — kuserd mints these, not them.
    gateway_tokens: Arc<RwLock<HashSet<String>>>,
    /// Sessions kuserd minted **for a third party** on a gateway's request:
    /// token → the principal it was minted for.
    ///
    /// A gateway holds no authority of its own beyond asking for one of these, so
    /// a compromised gateway inherits the principals currently connected rather
    /// than the whole account.
    principal_sessions: Arc<RwLock<HashMap<String, kotton_wire::ipc::Principal>>>,
    /// Live TLS allowlist â€” raw Ed25519 verifying-key bytes for every paired peer.
    ///
    /// Seeded from `paired_nodes` at startup; updated in-place when a node is
    /// inserted (`insert_paired_node`) or revoked (`NodeRevoke`).  Passed to the
    /// QUIC transport so the TLS handshake can check the peer's certificate.
    paired_keys: Arc<RwLock<HashSet<[u8; 32]>>>,
    /// Parked SAS confirmations for the streamed pairing ceremony.
    ///
    /// Maps a ceremony token → the oneshot a `PairConfirmCode` request fires with
    /// the human's verdict, so the parked `DeviceAdd`/`DeviceJoin` stream can
    /// proceed.
    pending_confirms: kotton_peer::daemon::nodes::PendingConfirms,
    /// Open `WebShellPair` desks, by user: a browser with an unknown key is
    /// admitted only if a human has one open on a trusted screen.
    browser_desks: browser_channel::BrowserDesks,
    /// Contact ceremonies in flight. One per daemon,
    /// because a ceremony outlives the host call that starts it.
    ceremonies: ceremony::Ceremonies,
    /// Browser channels reached through a gateway device over the relay,
    /// keyed by gateway and channel name.
    browser_channels: browser_channel::BrowserChannels,
    /// Reassembly buffers for chunked local `WriteFile`s — a large
    /// file arrives from the client as a run of chunks accumulated here until
    /// complete. Content-hash-keyed like the peer sealed-write buffers.
    file_reassembly: kotton_device::users::files::SealedReassembly,
    /// In-memory revocation set for ephemeral guest sessions.
    ///
    /// Seeded from `ephemeral_sessions` (revoked = 1) at startup; updated
    /// in-place when `SessionEnd` is processed.  Allows `handle_peer_request`
    /// to reject revoked sessions without a DB round-trip.
    revoked_sessions: Arc<RwLock<HashSet<String>>>,
    /// Sync engine — coalescing scheduler, job registry, background loop.
    ///
    /// Holds the `wake_background` notifier used by the VFS watcher and peer-push
    /// handlers to trigger the background poll without waiting for the 5-minute tick.
    sync_engine: Arc<kotton_sync::engine::SyncEngine>,
    /// The same per-user seam the sync engine holds, kept so dispatch can lend it
    /// to `file_host` without rebuilding one per request. All four locators behind
    /// it are `Arc`-backed, so this is the same bookkeeping, not a copy of it.
    sync_resources: Arc<dyn kotton_sync::SyncHost>,
    /// Broadcast channel for VFS filesystem-change notifications.
    ///
    /// Sent by `spawn_fs_watcher` on every notify event; subscribed by
    /// `handle_vfs_watch` per active `VfsWatch` IPC connection.
    vfs_watch_tx: tokio::sync::broadcast::Sender<kotton_sync::engine::VfsChangeFrame>,
    /// Persistent long-lived runner processes, keyed by app_id.
    live_instances:
        Arc<tokio::sync::Mutex<HashMap<String, kotton_app::daemon::apps::LongLivedInstance>>>,
    /// Live sidecar process state, keyed by process name (e.g. `"ksyncd"`).
    ///
    /// Pre-populated at startup with a `"kuserd"` entry (self).
    sidecar_states: Arc<RwLock<HashMap<String, SidecarState>>>,
    /// Live IPC session records, keyed by session token.
    ///
    /// Inserted on successful `Authenticate`; removed on `LockSession` or connection drop.
    ipc_sessions: Arc<RwLock<HashMap<String, IpcSessionRecord>>>,
    /// Currently connected peer DIDs, as last reported by ksyncd via `VfsReport`.
    ///
    /// Updated atomically when a `VfsReport` IPC message arrives from ksyncd.
    /// Used by `SyncStatus` and `NetworkStatus` to report live connectivity.
    connected_peers: Arc<RwLock<HashSet<String>>>,
    /// Proxy for forwarding surface patches and lifecycle events to `kuid`.
    ///
    /// All calls are fire-and-forget: if `kuid` is not running the proxy
    /// logs a warning and returns `Ok`.
    surface_proxy: Arc<SurfaceProxy>,
    /// The daemon's end of the inference channel to `kinferd`.
    ///
    /// Unlike [`Self::surface_proxy`], a call on this one that finds no runtime
    /// **fails** rather than warning: a dropped surface patch is a frame nobody
    /// drew, and a dropped question is a person waiting.
    infer_proxy: Arc<InferProxy>,
    /// Which app windows are open, per owner. See [`AgentContext::window_registry`].
    window_registry: Arc<dyn kotton_surface::WindowRegistry>,
    /// The binary that runs an app — `kotton-runner`, the sandbox as a process.
    ///
    /// Resolved once, here, at construction, to an absolute path:
    /// `KOTTON_RUNNER` if set (a dev checkout points it at its own build), else
    /// the one beside the daemon's own executable (an installed Kotton), else
    /// the first `kotton-runner` on `PATH` ([`resolve_runner`]). The app
    /// handlers used to read the variable themselves at every spawn, which
    /// made *which process is the sandbox* an ambient fact rather than one the
    /// daemon holds; the test harness sets it explicitly with
    /// [`Self::with_runner`], and nothing else can change it once the daemon
    /// is built.
    runner: PathBuf,
}

/// Where the daemon looks for its runner when nothing told it otherwise.
fn runner_from_environment() -> PathBuf {
    resolve_runner(
        std::env::var_os("KOTTON_RUNNER"),
        std::env::current_exe().ok().and_then(|exe| exe.parent().map(Path::to_path_buf)),
        std::env::var_os("PATH"),
        std::env::current_dir().ok(),
    )
}

/// The runner as an absolute path: `KOTTON_RUNNER` if set, else the
/// `kotton-runner` beside this daemon's own executable, else the first one on
/// `PATH` — resolved once, here.
///
/// **Beside the daemon before `PATH`**, so a friend can install Kotton without a
/// toolchain. An installed Kotton is one directory, and its daemon finds every
/// other process it starts beside itself (`sidecar_bin`), the runner included;
/// looked for by `PATH` first, an install would work only once someone added its
/// `bin/` to `PATH`, and then run whichever `kotton-runner` came first there.
/// Which process is the sandbox
/// is the last thing that should be decided by the order of a person's `PATH`:
/// the runner that shipped with this daemon is the one built against it. `PATH`
/// stays as the fallback for a daemon installed without one beside it.
///
/// Absolute because the sandbox grants the runner its own program by opening
/// it (`runner_profile` in `kotton-app`), and an open resolves a bare name
/// against the working directory, not `PATH`. Before the sandbox the bare name
/// went straight to `Command::new`, which searches `PATH` itself; handing the
/// same name to a grant turned every launch on a machine without
/// `KOTTON_RUNNER` into a refused grant. Doing the search the spawn used to do
/// keeps the binary that runs the one that was found, and keeps the daemon the
/// only place that decides it.
///
/// A relative `KOTTON_RUNNER` is anchored to the working directory at start,
/// for the same reason and so that a later `chdir` cannot change which
/// process is the sandbox. A name found nowhere is returned as it was given,
/// and the launch fails on it the way it did before.
fn resolve_runner(
    var: Option<std::ffi::OsString>,
    beside: Option<PathBuf>,
    path: Option<std::ffi::OsString>,
    cwd: Option<PathBuf>,
) -> PathBuf {
    let anchor = |p: PathBuf| match &cwd {
        Some(dir) if p.is_relative() => dir.join(p),
        _ => p,
    };
    if let Some(named) = var {
        return anchor(PathBuf::from(named));
    }
    let name = format!("kotton-runner{}", std::env::consts::EXE_SUFFIX);
    if let Some(shipped) = beside.map(|dir| anchor(dir.join(&name))) {
        if is_executable_file(&shipped) {
            return shipped;
        }
    }
    path.iter()
        .flat_map(std::env::split_paths)
        .map(|dir| anchor(dir.join(&name)))
        .find(|candidate| is_executable_file(candidate))
        .unwrap_or_else(|| PathBuf::from(name))
}

/// What `execvp` would accept at `path`: a regular file with an execute bit.
fn is_executable_file(path: &Path) -> bool {
    let Ok(meta) = std::fs::metadata(path) else {
        return false;
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        meta.is_file() && meta.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        meta.is_file()
    }
}

impl DeviceDaemon {
    /// Run apps with this binary instead of the one the environment named.
    ///
    /// For a harness that holds several daemons in one process and wants each
    /// to say which runner it spawns, rather than all of them reading one
    /// process-wide variable that any of them might set.
    pub fn with_runner(mut self, runner: PathBuf) -> Self {
        self.runner = runner;
        self
    }

    /// The binary this daemon runs apps with.
    pub fn runner(&self) -> &Path {
        &self.runner
    }

    /// The runtime this daemon serves.
    ///
    /// For tests and in-process tooling that need to reach runtime state the
    /// IPC surface deliberately does not expose — notably store-addressed
    /// access, which no protocol verb offers.
    pub fn runtime(&self) -> Arc<DeviceRuntime> {
        Arc::clone(&self.runtime)
    }

    /// The machine-wide pool, for a caller that needs to observe its state.
    ///
    /// Exists for `the_daemons_pools_are_closed_when_a_test_env_drops`, which
    /// holds that a test binary does not crash at exit with a pool still open.
    /// Counting clean full runs would not show it: at the crash rate once
    /// measured, five in a row happen by luck about 13% of the time. A closed
    /// pool is a fact about one run.
    pub fn machine_db(&self) -> Arc<SqlitePool> {
        Arc::clone(&self.db)
    }

    /// Which users are resident in this daemon.
    ///
    /// The counterpart to [`Self::runtime`], and the reason it exists: residency
    /// is the daemon's bookkeeping, so the machine cannot be asked. A caller
    /// that wants a resident user's runtime asks this, not `runtime()`.
    pub fn users(&self) -> crate::residency::UserRegistry {
        self.users.clone()
    }

    /// The user this daemon's sidecars act for.
    ///
    /// Under supervision by `kdeviced` exactly one user is loaded — the
    /// process's principal — so this is deterministic. On a legacy unsupervised
    /// boot it is an arbitrary loaded user, which is no worse than a machine-wide
    /// `SELECT DISTINCT user_id FROM paired_nodes` pick would be.
    fn sidecar_user(&self) -> Option<String> {
        self.users.any()
    }

    /// Create a new system daemon, initialising DeviceRuntime from the platform base directory.
    ///
    /// The base directory is resolved via [`kotton_common::base_dir`] (falls back
    /// to the `KOTTON_BASE_DIR` environment variable for dev overrides).
    pub async fn new(endpoint: IpcEndpoint) -> io::Result<Self> {
        let base = base_dir().map_err(|e| io::Error::other(e.to_string()))?;
        Self::new_with_base(base, endpoint).await
    }

    /// Create a daemon initialised from an explicit `base` directory.
    ///
    /// Bypasses the `KOTTON_BASE_DIR` environment-variable lookup so each
    /// integration-test instance can use its own isolated [`tempfile::TempDir`]
    /// without environment-variable races between parallel tests.
    ///
    /// # Startup order
    /// 1. Open & migrate `agent.db` first so `device_config` rows are available.
    /// 2. Load NAT settings (relay_url, turn_url, â€¦) from `device_config`.
    /// 3. Build `RuntimeConfig` with the persisted NAT settings.
    /// 4. Create `DeviceRuntime` with that config.
    pub async fn new_with_base(base: PathBuf, endpoint: IpcEndpoint) -> io::Result<Self> {
        // â”€â”€ Step 1: open the machine DB and run its migrations, once â”€â”€
        let events_db = base.join("system").join("agent.db");
        let db = crate::event_log::open_machine_db(&events_db)
            .await
            .map_err(|e| io::Error::other(format!("failed to open machine db: {e}")))?;
        // Device-scope config lives in device.db; opening it
        // also imports any legacy rows still sitting in agent.db.
        let device_db = kotton_device::db::open_device_db(&base, &db).await?;
        let nat = kotton_device::config::db::load_nat_config(&device_db).await?;
        let peer_listen_port_db =
            kotton_device::config::db::load_peer_listen_port(&device_db).await?;
        let peer_listen_port = peer_listen_port_db.or_else(|| {
            std::env::var("KOTTON_PEER_LISTEN_PORT")
                .ok()
                .and_then(|s| s.parse::<u16>().ok())
        });

        // â”€â”€ Step 3: build RuntimeConfig with persisted NAT settings â”€â”€
        let config = RuntimeConfig {
            nat,
            peer_listen_port,
            // When kdeviced spawned this process for one user, that
            // user is the only one this daemon loads or resolves keys for.
            principal: std::env::var("KOTTON_USER_DID").ok(),
            ..RuntimeConfig::default()
        };

        // â”€â”€ Step 4: create DeviceRuntime â”€â”€
        // Loading users is a daemon startup step, not part of building the
        // machine — see DeviceRuntime::load_users.
        let runtime = DeviceRuntime::new(base.clone(), config)
            .await
            .map_err(|e| io::Error::other(e.to_string()))?;
        // The daemon's registry of who is resident. It is created here, by the
        // daemon, rather than found on the machine: residency is the daemon's
        // bookkeeping, not the machine's.
        let users = crate::residency::UserRegistry::new();

        // Loading answers *which users may this process serve* (its principal
        // scoping); making them resident is this daemon's, so the
        // returned set is registered here rather than inside the load.
        //
        // Discarding this `Vec` compiles perfectly and starts a daemon with no
        // resident users: once an act becomes a return value, `?` stops the
        // compiler helping, so the registration below is the act.
        for (user_id, user_rt) in runtime
            .load_users()
            .await
            .map_err(|e| io::Error::other(e.to_string()))?
        {
            users.insert(user_id, user_rt);
        }

        let db = Arc::new(db);

        // â”€â”€ Step 6: per-user databases; bundled apps + roles per user â”€â”€â”€â”€â”€â”€â”€â”€
        // One loaded principal under supervision, every
        // loaded user on a legacy unsupervised boot. A user whose database
        // fails to open still gets a running daemon — their apps simply are
        // not seeded until the cause is fixed.
        let user_dbs: crate::db::user_db::UserDbMap = Arc::new(RwLock::new(HashMap::new()));
        let loaded_users: Vec<String> = users.ids();
        let mut apps_installed = 0u32;
        let mut revoked_ids: HashSet<String> = HashSet::new();
        for uid in &loaded_users {
            match crate::db::user_db::user_agent_db(
                &user_dbs,
                &base,
                runtime.secrets(),
                uid,
                &runtime.schema_registry,
            )
            .await
            {
                Ok(user_db) => {
                    // Default roles are seeded by the open itself (user_db.rs).
                    auto_install_bundled_apps(&user_db, &base, uid, runtime.secrets()).await;
                    apps_installed += app_registry_db::count_apps(&user_db).await.unwrap_or(0);
                    // Revoked guest-session ids live per-user now (3b-v); the
                    // in-memory rejection set is the union over loaded users.
                    revoked_ids.extend(
                        kotton_peer::daemon::db::list_revoked_session_ids(&user_db)
                            .await
                            .unwrap_or_default(),
                    );
                }
                Err(e) => {
                    eprintln!("[daemon] warning: user agent db for '{uid}' failed to open: {e}")
                }
            }
        }

        // Per-principal event logs, each chained under
        // its own user's key — armed for the first time in production; the old
        // machine log only ever wrote unsigned cold-start sentinels. Device
        // lifecycle keeps a log of its own, which no user's key chains.
        let event_log_tasks: crate::event_log::EventLogTasks = Default::default();
        let device_log_task = spawn_device_event_log(&runtime, &db);
        for uid in &loaded_users {
            spawn_user_event_log(&runtime, &user_dbs, &base, &event_log_tasks, uid).await;
        }

        // Emit startup event now that the subscriber is wired.
        let _ = runtime
            .event_bus()
            .publish(kotton_diag::service::Event::with_payload(
                kotton_diag::service::EventCategory::System,
                kotton_diag::service::EventLevel::Info,
                "Daemon started",
                serde_json::json!({
                    "base_dir": base.display().to_string(),
                    "apps_installed": apps_installed,
                }),
            ));

        // â”€â”€ Step 7: seed paired_keys from DB â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        // Any error loading keys is non-fatal: worst case is an empty allowlist
        // (no peers can connect until the daemon restarts with a fresh DB).
        // One allowlist, owned by the runtime's reachability handle: the set the
        // TLS handshake admits from is the set presence announces to, and a
        // second copy would drift the day one was updated and the other was not.
        //
        // Built per loaded user, never across all of them: the allowlist is the
        // union of per-user contributions, present while the contributing daemon
        // runs. Seeding across every user admits a
        // locked user's peer, who then completes the handshake and fails on
        // keys — saying "the machine is up and your user is not available",
        // which is the one sentence that section exists to unsay.
        let paired_keys = runtime.paired_keys();
        {
            let resolved: Vec<(String, Arc<dyn kotton_peer::membership::MemberStore>)> = users
                .all()
                .into_iter()
                .map(|(id, rt)| (id, rt as Arc<dyn kotton_peer::membership::MemberStore>))
                .collect();
            kotton_peer::daemon::nodes::reproject_allowlist(&resolved, &db, &paired_keys).await;
            // The same per-loaded-user rule for what the listener can admit on
            // proof: the identity tips and recovery authorities this node holds.
            // A locked user's identity is not admittable while its user is not,
            // for the reason given above.
            let user_ids: Vec<String> = resolved.iter().map(|(id, _)| id.clone()).collect();
            kotton_device::users::admission::reproject(&base, &user_ids, &runtime.admission());
        }

        // â”€â”€ Step 8: seed revoked session IDs from DB â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        let revoked_sessions = Arc::new(RwLock::new(revoked_ids));

        let runtime = Arc::new(runtime);
        // The daemon's second residency map. Built here so the sync engine and
        // the context share one cache rather than opening a store each.
        let record_stores = crate::residency::RecordStores::new();
        // The daemon lends the engine its three locators through one seam, so the
        // engine names no daemon type. See `residency::DaemonUserResources`.
        let sync_resources: Arc<dyn kotton_sync::SyncHost> =
            crate::residency::DaemonUserResources::new(
                users.clone(),
                record_stores.clone(),
                Arc::clone(&user_dbs),
                Arc::clone(&runtime),
                Some(Arc::clone(&db)),
            );
        let sync_engine = kotton_sync::engine::SyncEngine::new(
            Arc::clone(&db),
            Arc::clone(&runtime),
            Arc::clone(&sync_resources),
            Arc::clone(&paired_keys),
        );
        // A pack a device does not keep is fetched from the person's drives
        // when something reads it (kotton #55).
        users.lend_packs(sync_engine.pack_source());
        // Hoisted out of the literal below because the ceremony registry needs
        // them: it is built here rather than lazily so there is one, made once,
        // for the life of the daemon.
        let sessions: sessions::SessionMap = Arc::new(RwLock::new(HashMap::new()));
        let live_instances = Arc::new(tokio::sync::Mutex::new(HashMap::new()));
        let pending_confirms: kotton_peer::daemon::nodes::PendingConfirms =
            Arc::new(tokio::sync::Mutex::new(HashMap::new()));
        let surface_proxy = Arc::new(SurfaceProxy::new());
        let runner = runner_from_environment();
        // One per daemon, made here rather than in the struct literal below
        // because `Ceremonies` now carries it too and both must be the same
        // channel — two `InferProxy`s would mean a guest's answer depending on
        // which frame it asked from.
        let infer_proxy = Arc::new(InferProxy::new());
        // Made here rather than in the struct literal below for the reason
        // `infer_proxy` is: `Ceremonies` carries both too, and two
        // connected-peer sets would mean a readout's answer depending on which
        // frame asked.
        let device_db = Arc::new(device_db);
        let connected_peers: Arc<RwLock<HashSet<String>>> = Arc::new(RwLock::new(HashSet::new()));
        // Hoisted for the same reason `sessions` is: the ceremony registry
        // builds occupant hosts, and a host's browser revoke must end the
        // sessions and channels this daemon actually holds.
        let principal_sessions: Arc<RwLock<HashMap<String, kotton_wire::ipc::Principal>>> =
            Arc::new(RwLock::new(HashMap::new()));
        let browser_channels: browser_channel::BrowserChannels =
            Arc::new(tokio::sync::Mutex::new(HashMap::new()));
        let ceremonies = ceremony::Ceremonies::new(
            Arc::clone(&runtime),
            users.clone(),
            Arc::clone(&sessions),
            base.clone(),
            Arc::clone(&db),
            record_stores.clone(),
            Arc::clone(&infer_proxy),
            Arc::clone(&paired_keys),
            Arc::clone(&pending_confirms),
            Arc::clone(&live_instances),
            Arc::clone(runtime.event_bus()),
            Arc::clone(&surface_proxy),
            runner.clone(),
            runtime.secrets_arc(),
            Arc::clone(&user_dbs),
            Arc::clone(&event_log_tasks),
            Arc::clone(&device_db),
            Arc::clone(&connected_peers),
            browser_channel::BrowserAdmissions::new(
                Arc::clone(&sessions),
                Arc::clone(&principal_sessions),
                Arc::clone(&browser_channels),
            ),
            sync_engine.hand_over_signal(),
        );
        Ok(Self {
            ceremonies,
            users: users.clone(),
            record_stores: record_stores.clone(),
            runtime: Arc::clone(&runtime),
            endpoint,
            db,
            device_db,
            user_dbs,
            event_log_tasks,
            base,
            started_at: Instant::now(),
            sessions,
            gateway_tokens: Arc::new(RwLock::new(HashSet::new())),
            principal_sessions,
            paired_keys,
            pending_confirms,
            browser_desks: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            browser_channels,
            file_reassembly: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            sync_engine,
            sync_resources,
            vfs_watch_tx: tokio::sync::broadcast::channel(64).0,
            live_instances,
            revoked_sessions,
            sidecar_states: {
                use std::time::{SystemTime, UNIX_EPOCH};
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as i64;
                let mut map = HashMap::new();
                map.insert(
                    "kuserd".to_string(),
                    SidecarState {
                        enabled: true,
                        running: true,
                        pid: Some(std::process::id()),
                        port: None,
                        restart_count: 0,
                        started_at: Some(now),
                        failed: None,
                    },
                );
                Arc::new(RwLock::new(map))
            },
            ipc_sessions: Arc::new(RwLock::new(HashMap::new())),
            connected_peers,
            surface_proxy: Arc::new(SurfaceProxy::new()),
            infer_proxy: Arc::clone(&infer_proxy),
            window_registry: kotton_surface::InMemoryWindowRegistry::new(),
            runner: runner_from_environment(),
            device_log_task: std::sync::Mutex::new(Some(device_log_task)),
            quit: Arc::new(tokio::sync::watch::channel(false).0),
        })
    }

    /// Like [`new_with_base`] but injects a custom secrets store.
    ///
    /// Used by integration tests to inject `MemorySecrets` instead of the OS
    /// keychain, avoiding Windows Credential Manager contention between parallel
    /// test processes.
    pub async fn new_with_base_and_secrets(
        base: PathBuf,
        endpoint: IpcEndpoint,
        secrets: Arc<dyn SecretsStore + Send + Sync>,
    ) -> io::Result<Self> {
        Self::new_with_base_secrets_and_relay(base, endpoint, secrets, RelayChoice::Configured)
            .await
    }

    /// Like [`new_with_base_and_secrets`](Self::new_with_base_and_secrets) but
    /// with the relay this daemon reserves at handed in.
    ///
    /// `RelayChoice::Configured` is the deployment path and what every binary
    /// entry point uses: the device's own row, and a device nobody told has no
    /// relay — nothing fills one from the environment. Naming one here is for a
    /// caller that builds several daemons in one process and says, of each,
    /// which relay *this* daemon reserves at. The base dir, the endpoint and the
    /// secrets store are handed in for the same reason, so tests that run in
    /// parallel share no process-global state.
    pub async fn new_with_base_secrets_and_relay(
        base: PathBuf,
        endpoint: IpcEndpoint,
        secrets: Arc<dyn SecretsStore + Send + Sync>,
        relay: RelayChoice,
    ) -> io::Result<Self> {
        Self::new_supervised(
            base,
            endpoint,
            secrets,
            relay,
            Supervision {
                principal: std::env::var("KOTTON_USER_DID").ok(),
                kdeviced: None,
            },
        )
        .await
    }

    /// Like [`new_with_base_secrets_and_relay`](Self::new_with_base_secrets_and_relay),
    /// with **who this process serves and who supervises it** handed in rather
    /// than read from `KOTTON_USER_DID` and the machine's `kdeviced` socket —
    /// both process-wide, so a caller building several daemons in one process
    /// (the suite, standing up one person's daemon beside another's on one
    /// machine, as `kdeviced` spawns them) says it to each.
    pub async fn new_supervised(
        base: PathBuf,
        endpoint: IpcEndpoint,
        secrets: Arc<dyn SecretsStore + Send + Sync>,
        relay: RelayChoice,
        supervision: Supervision,
    ) -> io::Result<Self> {
        let events_db = base.join("system").join("agent.db");
        let db = crate::event_log::open_machine_db(&events_db)
            .await
            .map_err(|e| io::Error::other(format!("failed to open machine db: {e}")))?;
        // Device-scope config lives in device.db; opening it
        // also imports any legacy rows still sitting in agent.db.
        let device_db = kotton_device::db::open_device_db(&base, &db).await?;
        let nat = kotton_device::config::db::load_nat_config_with(&device_db, relay).await?;
        let peer_listen_port_db =
            kotton_device::config::db::load_peer_listen_port(&device_db).await?;
        let peer_listen_port = peer_listen_port_db.or_else(|| {
            std::env::var("KOTTON_PEER_LISTEN_PORT")
                .ok()
                .and_then(|s| s.parse::<u16>().ok())
        });

        let config = RuntimeConfig {
            nat,
            peer_listen_port,
            // When kdeviced spawned this process for one user, that
            // user is the only one this daemon loads or resolves keys for.
            principal: supervision.principal,
            kdeviced: supervision.kdeviced,
            ..RuntimeConfig::default()
        };

        let runtime = DeviceRuntime::new_with_secrets(base.clone(), config, secrets)
            .await
            .map_err(|e| io::Error::other(e.to_string()))?;
        // The daemon's registry of who is resident. It is created here, by the
        // daemon, rather than found on the machine: residency is the daemon's
        // bookkeeping, not the machine's.
        let users = crate::residency::UserRegistry::new();

        // Loading answers *which users may this process serve* (its principal
        // scoping); making them resident is this daemon's, so the
        // returned set is registered here rather than inside the load.
        //
        // Discarding this `Vec` compiles perfectly and starts a daemon with no
        // resident users: once an act becomes a return value, `?` stops the
        // compiler helping, so the registration below is the act.
        for (user_id, user_rt) in runtime
            .load_users()
            .await
            .map_err(|e| io::Error::other(e.to_string()))?
        {
            users.insert(user_id, user_rt);
        }

        let db = Arc::new(db);

        // Per-user databases; bundled apps + roles per user.
        let user_dbs: crate::db::user_db::UserDbMap = Arc::new(RwLock::new(HashMap::new()));
        let loaded_users: Vec<String> = users.ids();
        let mut apps_installed = 0u32;
        let mut revoked_ids: HashSet<String> = HashSet::new();
        for uid in &loaded_users {
            match crate::db::user_db::user_agent_db(
                &user_dbs,
                &base,
                runtime.secrets(),
                uid,
                &runtime.schema_registry,
            )
            .await
            {
                Ok(user_db) => {
                    // Default roles are seeded by the open itself (user_db.rs).
                    auto_install_bundled_apps(&user_db, &base, uid, runtime.secrets()).await;
                    apps_installed += app_registry_db::count_apps(&user_db).await.unwrap_or(0);
                    // Revoked guest-session ids live per-user now (3b-v); the
                    // in-memory rejection set is the union over loaded users.
                    revoked_ids.extend(
                        kotton_peer::daemon::db::list_revoked_session_ids(&user_db)
                            .await
                            .unwrap_or_default(),
                    );
                }
                Err(e) => {
                    eprintln!("[daemon] warning: user agent db for '{uid}' failed to open: {e}")
                }
            }
        }

        let event_log_tasks: crate::event_log::EventLogTasks = Default::default();
        let device_log_task = spawn_device_event_log(&runtime, &db);
        for uid in &loaded_users {
            spawn_user_event_log(&runtime, &user_dbs, &base, &event_log_tasks, uid).await;
        }

        let _ = runtime
            .event_bus()
            .publish(kotton_diag::service::Event::with_payload(
                kotton_diag::service::EventCategory::System,
                kotton_diag::service::EventLevel::Info,
                "Daemon started",
                serde_json::json!({
                    "base_dir": base.display().to_string(),
                    "apps_installed": apps_installed,
                }),
            ));

        // One allowlist, owned by the runtime's reachability handle: the set the
        // TLS handshake admits from is the set presence announces to, and a
        // second copy would drift the day one was updated and the other was not.
        //
        // Built per loaded user, never across all of them: the allowlist is the
        // union of per-user contributions, present while the contributing daemon
        // runs. Seeding across every user admits a
        // locked user's peer, who then completes the handshake and fails on
        // keys — saying "the machine is up and your user is not available",
        // which is the one sentence that section exists to unsay.
        let paired_keys = runtime.paired_keys();
        {
            let resolved: Vec<(String, Arc<dyn kotton_peer::membership::MemberStore>)> = users
                .all()
                .into_iter()
                .map(|(id, rt)| (id, rt as Arc<dyn kotton_peer::membership::MemberStore>))
                .collect();
            kotton_peer::daemon::nodes::reproject_allowlist(&resolved, &db, &paired_keys).await;
        }

        let revoked_sessions = Arc::new(RwLock::new(revoked_ids));

        let runtime = Arc::new(runtime);
        // The daemon's second residency map. Built here so the sync engine and
        // the context share one cache rather than opening a store each.
        let record_stores = crate::residency::RecordStores::new();
        // One seam, as above — see `residency::DaemonUserResources`.
        let sync_resources: Arc<dyn kotton_sync::SyncHost> =
            crate::residency::DaemonUserResources::new(
                users.clone(),
                record_stores.clone(),
                Arc::clone(&user_dbs),
                Arc::clone(&runtime),
                Some(Arc::clone(&db)),
            );
        let sync_engine = kotton_sync::engine::SyncEngine::new(
            Arc::clone(&db),
            Arc::clone(&runtime),
            Arc::clone(&sync_resources),
            Arc::clone(&paired_keys),
        );
        // A pack a device does not keep is fetched from the person's drives
        // when something reads it (kotton #55).
        users.lend_packs(sync_engine.pack_source());
        // As in the constructor above: hoisted so the one ceremony registry can
        // be built from them before the literal.
        let sessions: sessions::SessionMap = Arc::new(RwLock::new(HashMap::new()));
        let live_instances = Arc::new(tokio::sync::Mutex::new(HashMap::new()));
        let pending_confirms: kotton_peer::daemon::nodes::PendingConfirms =
            Arc::new(tokio::sync::Mutex::new(HashMap::new()));
        let surface_proxy = Arc::new(SurfaceProxy::new());
        let runner = runner_from_environment();
        // One per daemon, made here rather than in the struct literal below
        // because `Ceremonies` now carries it too and both must be the same
        // channel — two `InferProxy`s would mean a guest's answer depending on
        // which frame it asked from.
        let infer_proxy = Arc::new(InferProxy::new());
        // Made here rather than in the struct literal below for the reason
        // `infer_proxy` is: `Ceremonies` carries both too, and two
        // connected-peer sets would mean a readout's answer depending on which
        // frame asked.
        let device_db = Arc::new(device_db);
        let connected_peers: Arc<RwLock<HashSet<String>>> = Arc::new(RwLock::new(HashSet::new()));
        // Hoisted for the same reason `sessions` is: the ceremony registry
        // builds occupant hosts, and a host's browser revoke must end the
        // sessions and channels this daemon actually holds.
        let principal_sessions: Arc<RwLock<HashMap<String, kotton_wire::ipc::Principal>>> =
            Arc::new(RwLock::new(HashMap::new()));
        let browser_channels: browser_channel::BrowserChannels =
            Arc::new(tokio::sync::Mutex::new(HashMap::new()));
        let ceremonies = ceremony::Ceremonies::new(
            Arc::clone(&runtime),
            users.clone(),
            Arc::clone(&sessions),
            base.clone(),
            Arc::clone(&db),
            record_stores.clone(),
            Arc::clone(&infer_proxy),
            Arc::clone(&paired_keys),
            Arc::clone(&pending_confirms),
            Arc::clone(&live_instances),
            Arc::clone(runtime.event_bus()),
            Arc::clone(&surface_proxy),
            runner.clone(),
            runtime.secrets_arc(),
            Arc::clone(&user_dbs),
            Arc::clone(&event_log_tasks),
            Arc::clone(&device_db),
            Arc::clone(&connected_peers),
            browser_channel::BrowserAdmissions::new(
                Arc::clone(&sessions),
                Arc::clone(&principal_sessions),
                Arc::clone(&browser_channels),
            ),
            sync_engine.hand_over_signal(),
        );
        Ok(Self {
            ceremonies,
            users: users.clone(),
            record_stores: record_stores.clone(),
            runtime: Arc::clone(&runtime),
            endpoint,
            db,
            device_db,
            user_dbs,
            event_log_tasks,
            base,
            started_at: Instant::now(),
            // The hoisted maps, not fresh ones: the ceremony registry above was
            // built from these, and a ceremony's host that held a different
            // session map from the daemon's would open sessions nobody resolves.
            sessions,
            gateway_tokens: Arc::new(RwLock::new(HashSet::new())),
            principal_sessions,
            paired_keys,
            pending_confirms,
            browser_desks: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            browser_channels,
            file_reassembly: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            sync_engine,
            sync_resources,
            vfs_watch_tx: tokio::sync::broadcast::channel(64).0,
            live_instances,
            revoked_sessions,
            sidecar_states: {
                use std::time::{SystemTime, UNIX_EPOCH};
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as i64;
                let mut map = HashMap::new();
                map.insert(
                    "kuserd".to_string(),
                    SidecarState {
                        enabled: true,
                        running: true,
                        pid: Some(std::process::id()),
                        port: None,
                        restart_count: 0,
                        started_at: Some(now),
                        failed: None,
                    },
                );
                Arc::new(RwLock::new(map))
            },
            ipc_sessions: Arc::new(RwLock::new(HashMap::new())),
            connected_peers,
            surface_proxy: Arc::new(SurfaceProxy::new()),
            infer_proxy: Arc::clone(&infer_proxy),
            window_registry: kotton_surface::InMemoryWindowRegistry::new(),
            runner: runner_from_environment(),
            device_log_task: std::sync::Mutex::new(Some(device_log_task)),
            quit: Arc::new(tokio::sync::watch::channel(false).0),
        })
    }

    /// Run the daemon, and close what it holds when serving ends.
    ///
    /// Taken as `Arc<Self>` rather than `self` so a caller can keep a handle
    /// while the daemon runs. The integration harness needs one: it ends a test
    /// by aborting this task, and an aborted future never reaches the teardown
    /// below — so without a handle the pools would stay live until process exit,
    /// and a test binary would crash at exit tearing them down.
    pub async fn run(self: Arc<Self>) -> io::Result<()> {
        let outcome = Arc::clone(&self).serve().await;
        self.shutdown().await;
        outcome
    }

    /// Close every custody window that has ended by `now`, as the sweep's timer
    /// does — for a caller that cannot wait for the timer. The daemon holds the
    /// caches a close must also forget, so the one-call form lives here.
    pub async fn close_expired_custody(&self, now: i64) -> Vec<String> {
        custody_window::close_expired(
            &self.runtime,
            &self.users,
            &self.user_dbs,
            &self.record_stores,
            &self.event_log_tasks,
            now,
        )
        .await
    }

    /// Drop this user's open databases — the cached `agent.db` pool and the open
    /// `records.db` store — the way stopping the daemon does.
    ///
    /// **This exists because the suite's model of a restart was missing half of one,
    /// and then a third of one.** `TestEnv::lock_as_a_restart_would` locks memory
    /// custody and rebuilds the resident user, which is the object store's part — and
    /// leaves every *other* keyed handle this daemon opened while the key was there
    /// sitting in its cache, where every later read finds it and succeeds. A process
    /// that actually restarted would hold none of them.
    ///
    /// After that helper alone, `app_list` still answers with both bundled apps,
    /// because the `agent.db` pool is still in `user_dbs`; with the `agent.db` half
    /// and not the rest, the inbox and the unread count still answer, because
    /// `RecordStores` holds the `records.db` handle the message host opened while
    /// the account was open. Same shape each time — *looks
    /// like it produces this state and does not* — one cache further out.
    ///
    /// Not a test-only hook in disguise: `shutdown` performs exactly this for every
    /// user, and this names the one-user case so a caller that is modelling a restart
    /// can reach it. The suite never restarts a real daemon; a test that did
    /// would make the modelling unnecessary.
    pub async fn evict_open_databases(&self, user_id: &str) {
        // Close the pool, then **drop the marker too**. `evict` alone leaves `Closing`
        // behind, which is right for a logout — it stops a background pass reopening the
        // file mid-teardown — and wrong for this, because the next read then answers
        // *"being logged out; their database is closed"* rather than going through
        // `resolve_master` and finding no key. A restarted process holds neither the pool
        // nor the marker, and it is the *second* absence that makes the account read as
        // locked.
        //
        // The event-log task first, for the reason `LogoutUser` stops it first: it
        // owns a clone of the pool `evict` is about to close, and a restarted
        // process that has not been unlocked runs no log for this account.
        crate::event_log::stop_user_log(&self.event_log_tasks, user_id).await;
        crate::db::user_db::evict(&self.user_dbs, user_id).await;
        crate::db::user_db::release(&self.user_dbs, user_id);
        // The record store opens with the key it resolves at open time and keeps it,
        // so the next reach for it after this reopens and finds none.
        self.record_stores.remove(user_id);
    }

    /// Close what this daemon holds, innermost holder first, before the process
    /// reaches `exit()`.
    ///
    /// The order is `LogoutUser`'s, for the same reason: a holder that still owns
    /// a pool clone when that pool closes is a race, and the event-log task is
    /// the holder no eviction path reaches. Producers stop first so nothing new
    /// arrives mid-teardown, then per-user state, then the machine pools
    /// everything above writes through.
    ///
    /// Deliberately not `Drop`: every step here awaits, and a `Drop` that cannot
    /// await is how the ordering silently degrades back into the race it
    /// replaces.
    pub async fn shutdown(&self) {
        // Producers first: background accept tasks would otherwise keep handing
        // work to stores being closed underneath them.
        if let Err(e) = self.runtime.shutdown().await {
            // "Runtime not started" is the ordinary answer when `run` failed
            // before `start`, so this is debug rather than a warning.
            tracing::debug!("runtime shutdown: {e}");
        }

        for (user_id, _) in self.users.all() {
            // Awaited, not merely aborted: `abort` only *requests* cancellation,
            // and the pool clone the task owns outlives the request.
            crate::event_log::stop_user_log(&self.event_log_tasks, &user_id).await;
            self.record_stores.remove(&user_id);
            self.users.remove(&user_id);
            crate::db::user_db::evict(&self.user_dbs, &user_id).await;
        }

        // The device log writes into `db`, so it stops before `db` closes — the
        // machine-scope twin of `stop_user_log` above.
        let device_log = self.device_log_task.lock().unwrap().take();
        if let Some(handle) = device_log {
            handle.abort();
            let _ = handle.await;
        }

        // Machine pools last. Closing these first would pull the floor out from
        // under the per-user teardown above, which reads and writes through them.
        crate::db::close_pool(&self.db).await;
        crate::db::close_pool(&self.device_db).await;

        tracing::info!("shutdown complete");
    }

    /// Start services, then serve until the listener fails. Errors return to
    /// [`Self::run`], which owns the teardown.
    async fn serve(self: Arc<Self>) -> io::Result<()> {
        let this = self;

        // Install the compositor's event sink before anything can supervise a
        // `kuid`. An event arriving with no sink is dropped, and the window
        // between spawning a compositor and being ready to hear from it is
        // exactly when its first frames land.
        this.start_compositor_events();

        // Start the runtime's configured transports and discovery. The accept
        // loops do not read this: each ends when its listener closes or its
        // handle is aborted, which shutdown does.
        this.runtime.start().await.map_err(io::Error::other)?;

        // â”€â”€ Auto-start peer listener if configured â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        //
        // The QUIC socket is optional — plenty of machines cannot bind one
        // anybody can reach. The relay reservations are not: they are the
        // inbound path for exactly those machines, and a contact's mailbox
        // is one of them, so they start either way.
        if let Some(port) = this.runtime.config().peer_listen_port {
            this.start_peer_listener_background(port)
                .await
                .map_err(io::Error::other)?;
        } else {
            this.runtime
                .start_relay_reservations(this.build_peer_handler());
        }

        // ── The local-network door ─────────────────────────────────────────
        // Closed unless the person opened it: the keeper holds nothing until the
        // row says *10 minutes*, or this is the network *Always* is kept for:
        // the local network is a door opened on purpose, for ten minutes.
        handlers::device_config::restore_local_door(&this.runtime, &this.device_db).await?;
        this.runtime.spawn_local_door_keeper(this.build_peer_handler());
        // ── Introductions ──────────────────────────────────────────────────
        // Nothing is bound until one of the person's devices, reached through a
        // relay both are on, asks; then one listener, for that device, for one
        // session. A relay introduces your devices.
        this.runtime.serve_introductions(this.build_peer_handler());

        // â”€â”€ Spawn background sync engine â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
        // ── The contact mailboxes ───────────────────────────────────────────
        // Built before anything can be delivered, and rebuilt when a pairing
        // admits someone. Reachability turns the registry into reservations on
        // its next pass, so a mailbox opens about a second after its pairing.
        // A pass that could not read everything keeps the doors it would have
        // replaced and is tried again on a backoff until one can
        // (`mailbox::keep_rebuilt`).
        {
            let mut rebuild = mailbox::Mailboxes {
                runtime: Arc::clone(&this.runtime),
                users: this.users.clone(),
                record_stores: this.record_stores.clone(),
                db: Arc::clone(&this.db),
                kept: mailbox::Kept::default(),
            };
            let held = mailbox::Rebuild::rebuild(&mut rebuild).await;
            let changed = this.runtime.contacts_changed();
            tokio::spawn(mailbox::keep_rebuilt(changed, held, mailbox::RETRY, rebuild));
        }
        // Each person's reach note: re-signed when this device's relays change
        // and sent sealed to every contact, so a card follows a move. The note is
        // signed by its person, and it is what a contact reaches them by.
        reach_keeper::spawn(
            Arc::clone(&this.runtime),
            this.users.clone(),
            this.record_stores.clone(),
        );
        // The outbox: a direct message a device of the recipient's has not yet
        // signed for is tried again until one does.
        outbox_keeper::spawn(
            Arc::clone(&this.runtime),
            this.users.clone(),
            this.record_stores.clone(),
        );
        // Custody's end: identities whose window has closed are locked, and
        // their stores rebuilt without a key, on a timer, so an unlock ends and
        // its end is reported.
        custody_window::spawn(
            Arc::clone(&this.runtime),
            this.users.clone(),
            this.user_dbs.clone(),
            this.record_stores.clone(),
            Arc::clone(&this.event_log_tasks),
        );
        // The vault's doors: topped up and picked up on a timer.
        vault_doors::spawn(
            Arc::clone(&this.runtime),
            Arc::clone(&this.db),
            this.users.clone(),
            this.record_stores.clone(),
        );

        // -- Spawn background sync engine ----------------------------------------------------
        Arc::clone(&this.sync_engine).spawn_background();

        // â"€â"€ Spawn filesystem watch â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
        // Bound to a name, not `let _ =`. `let _ =` drops the handle immediately,
        // which stops the watcher before the first request — the binding is what
        // keeps the watch alive, and it lives until this function returns, which
        // is daemon shutdown.
        let fs_watcher = kotton_sync::engine::spawn_fs_watcher(
            this.runtime.base_dir().clone(),
            Arc::clone(&this.sync_engine),
            this.vfs_watch_tx.clone(),
        );
        // Whether that thread has registered its watch yet. `VfsWatch`'s first
        // frame is derived from it, so a subscriber learns the watch is live
        // instead of guessing from a silence.
        let fs_watch_state = fs_watcher.state();

        let server =
            ChannelAcceptor::<UserRequest, UserResponse>::listen(this.endpoint.clone()).await?;

        // â"€â"€ Spawn ksyncd sidecar if paired nodes exist â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€
        {
            // The daemon's own user, not an arbitrary row from a machine-wide
            // table: under supervision exactly one user is loaded, and the
            // sidecar acts for that principal only. And ksyncd earns its process
            // only once a peer is paired.
            let first_user = match this.sidecar_user() {
                Some(user_id) => {
                    // An error reads as "no peers": the sidecar simply does not
                    // spawn until the next boot.
                    let has_peers = kotton_peer::daemon::db::list_paired_nodes(&this.db, &user_id)
                        .await
                        .map(|nodes| !nodes.is_empty())
                        .unwrap_or(false);
                    has_peers.then_some(user_id)
                }
                None => None,
            };

            if let Some(user_id) = first_user {
                let token =
                    sidecar_token::SidecarToken::new(Arc::clone(&this.sessions), None, user_id);
                let endpoint = this.endpoint.clone();
                tokio::spawn(supervise_ksyncd(
                    token,
                    endpoint,
                    Arc::clone(&this.sidecar_states),
                ));
            }
        }
        // ── Spawn kquicd sidecar if quic-gateway.enabled = "true" ─────────────────────
        {
            let gw_enabled =
                kotton_device::config::db::get_key(this.device_db.as_ref(), "quic-gateway.enabled")
                    .await
                    .ok()
                    .flatten()
                    .map(|v| v == "true")
                    .unwrap_or(false);

            if gw_enabled {
                // The daemon's own user, not an arbitrary user_id out of the
                // machine-wide paired_nodes.
                let first_user = this.sidecar_user();

                if let Some(user_id) = first_user {
                    // kquicd is a gateway → its sessions are Remote.
                    let token = sidecar_token::SidecarToken::new(
                        Arc::clone(&this.sessions),
                        Some(Arc::clone(&this.gateway_tokens)),
                        user_id,
                    );
                    let endpoint = this.endpoint.clone();
                    tokio::spawn(supervise_kquicd(
                        token,
                        endpoint,
                        Arc::clone(&this.sidecar_states),
                    ));
                }
            }
        }
        // ── Spawn khttpd sidecar if web-shell.enabled = "true" ─────────────
        ensure_khttpd(&this.agent_context()).await;

        // ── Spawn kinferd if inference.enabled = "true" ─────────────────────
        //
        // Off by default, on the `quic-gateway.enabled` pattern rather than
        // `display-server.enabled`'s: a gateway earns its process when the
        // person turns it on, and so does this. Until `kotton model add` exists
        // there is nothing for the runtime to load, so the default costs a process
        // and buys nothing.
        //
        // **This gate is a placeholder for a better one**, and the better one is
        // named: once a model is a record in the person's store, "is a model
        // installed?" is the condition that should start the runtime, exactly as
        // "are there paired nodes?" starts `ksyncd`. Named here so the swap is a
        // step rather than a discovery.
        {
            // `ops::inference`, not a raw `get_key`: the key has one reader and
            // one writer and they are the same three lines, which is what
            // `set_inference`'s doc means by a named wrapper.
            let inference_enabled = kotton_device::config::ops::inference(this.device_db.as_ref())
                .await
                .unwrap_or(false);

            if inference_enabled {
                tokio::spawn(supervise_kinferd(
                    sidecar_bin("kinferd"),
                    Arc::clone(&this.sidecar_states),
                    Arc::clone(&this.infer_proxy),
                ));
            } else {
                // A row that says "off" rather than no row at all. `kotton
                // sidecars` lists what it finds in this map, so a sidecar that
                // is switched off and a sidecar that does not exist read
                // identically without this — and "off" is the state a person
                // most needs to be told about, because it is the one they can
                // change.
                this.sidecar_states.write().unwrap().insert(
                    "kinferd".to_string(),
                    SidecarState {
                        enabled: false,
                        running: false,
                        pid: None,
                        port: None,
                        restart_count: 0,
                        started_at: None,
                        failed: None,
                    },
                );
            }
        }

        // ── Spawn kuid compositor sidecar ───────────────────────────────────────────
        // Spawn kuid when the operator has not disabled it and the platform can
        // show a window.
        //
        // Two conditions, and there used to be three. The third was *at least
        // one app is registered*, read from the resident user's app registry —
        // which meant a display server required a user, because the registry is
        // per-user. On a machine nobody has logged into
        // there is no registry to count, so the count was zero, so no compositor
        // started, so first run had nothing to draw on.
        //
        // The count was standing in for "is there anything worth showing?" It
        // was answering that from the wrong side. What is worth showing on a
        // fresh machine is the welcome screen, and requiring an app registry to
        // decide that guarantees the one case it most needs to allow is the one
        // it refuses.
        //
        // What made it removable is that kuid no longer needs a session: it is
        // authorised by the descriptor it is handed, so there is no user to
        // resolve before spawning it and nothing to look a registry up for.
        {
            let display_enabled = kotton_device::config::db::get_key(
                this.device_db.as_ref(),
                "display-server.enabled",
            )
            .await
            .ok()
            .flatten()
            .map(|v| v != "false")
            .unwrap_or(true);

            #[cfg(target_os = "linux")]
            let display_available = std::env::var_os("DISPLAY").is_some()
                || std::env::var_os("WAYLAND_DISPLAY").is_some();
            #[cfg(not(target_os = "linux"))]
            let display_available = true;

            if display_enabled && display_available {
                tokio::spawn(supervise_kuid(
                    Arc::clone(&this.sidecar_states),
                    Arc::clone(&this.surface_proxy),
                    this.quit.subscribe(),
                ));

                // Draw something. Nothing else will: `kuid` used to resolve the
                // `shell` role and launch it, and that work moved here when its
                // client connection went away — so if the daemon does not start
                // the desktop, no part of the system does.
                //
                // Spawned rather than awaited: the compositor is still forking,
                // and the first `SurfaceOpen` is held in the proxy's backlog
                // until it attaches (`SurfaceProxy`, "What is sent before a
                // compositor attaches").
                //
                // Without that backlog the proxy would drop what arrives early,
                // and this one arrives about 14 ms before `supervise_kuid`
                // attaches on the owner's machine — so the desktop would never
                // appear.
                let shell = Arc::clone(&this);
                tokio::spawn(async move {
                    // No session at a boot: nobody has typed anything yet, so
                    // the shell opens on the welcome or unlock screen and gets
                    // no data mount. See `launch_designated_shell`.
                    let _ = shell.launch_designated_shell("boot", None).await;
                });
            }
        }
        println!("System daemon listening on {:?}", this.endpoint);

        let ctx = this.agent_context();
        // Still bound separately: these are used by the connection closure
        // itself rather than by request handling.
        let sessions = Arc::clone(&this.sessions);
        let sidecar_states = Arc::clone(&this.sidecar_states);
        let pending_confirms = Arc::clone(&this.pending_confirms);
        let browser_desks = Arc::clone(&this.browser_desks);
        let vfs_watch_tx = this.vfs_watch_tx.clone();
        // Bound out here for the same reason as the rest: the connection
        // closure hands it to `ensure_kuid_running`, which needs somewhere to
        // attach the surface channel when it starts kuid.
        let surface_proxy_for_kuid = Arc::clone(&this.surface_proxy);
        // **The one way out of serving that is not a failure.**
        //
        // Quitting Kotton stops the daemon; closing the window does not.
        // The accept loop below runs until the listener fails; quitting is the
        // other end of the same `serve`, so it is raced here rather than given
        // a path of its own. Whichever finishes, [`Self::run`] performs the
        // teardown, which is what *the same shutdown, not a second one* has to
        // mean in code.
        //
        // Cancelling the accept future drops whatever connections it was
        // driving, and that is right for this gesture: the person said they are
        // done, and a quit that waited for every open stream to close would
        // wait on a guest's convenience.
        // Subscribed before the accept future is built, so a quit that arrives
        // during startup is not missed: `wait_for` reads the current value
        // first, and the value is the whole state — a `Notify` would have to
        // store a permit for the same case, and would still say nothing to
        // `supervise_kuid`, which needs to *read* the flag rather than wait on
        // it (see [`kuid_left_the_window_up`]).
        let mut quitting = this.quit.subscribe();
        // A second handle, for the supervision a late `AppInstall` may start.
        let quitting_for_kuid = this.quit.subscribe();
        let accepting =
            server.accept_with_session_streaming(move |request, caller, conn_session| {
                let ctx = ctx.clone();
                let surface_proxy_for_kuid = Arc::clone(&surface_proxy_for_kuid);
                let quitting_for_kuid = quitting_for_kuid.clone();
                let sessions = Arc::clone(&sessions);
                let sidecar_states = Arc::clone(&sidecar_states);
                let pending_confirms = Arc::clone(&pending_confirms);
                let browser_desks = Arc::clone(&browser_desks);
                let vfs_watch_tx = vfs_watch_tx.clone();
                let fs_watch_state = fs_watch_state.clone();
                async move {
                    // A verb its client reads as a stream is answered as one,
                    // refusal included: `streamed::answer`'s type is the stream,
                    // so no answer to it can be one frame left open (#120).
                    if let Some(stream) = streamed::answer(
                        &ctx,
                        &request,
                        &conn_session,
                        streamed::VfsWatchSource {
                            changes: &vfs_watch_tx,
                            watcher: &fs_watch_state,
                        },
                    )
                    .await
                    {
                        return stream.map(HandlerOutput::Stream);
                    }
                    // The same gate for a verb answered in one frame, before
                    // anything below runs; `handle_request` reads it again.
                    if let Some(refusal) =
                        dispatch::stream_entry_refusal(&sessions, &conn_session, &request)
                    {
                        return Ok(HandlerOutput::Single(refusal));
                    }
                    // One relayed frame of a browser's sealed channel.
                    if let UserRequest::BrowserFrame { bytes, channel, user_id } = request {
                        let resp = browser_channel::handle_frame(
                            &ctx,
                            caller,
                            &conn_session,
                            &pending_confirms,
                            &browser_desks,
                            user_id,
                            channel,
                            bytes,
                        )
                        .await;
                        return Ok(HandlerOutput::Single(resp));
                    }
                    // Ensure kuid is running before any app install or launch.
                    // kuid is normally started at daemon boot when apps are already
                    // registered, but sideloads that happen after the daemon starts
                    // would otherwise never trigger kuid supervision.
                    if matches!(
                        request,
                        UserRequest::AppInstall { .. } | UserRequest::AppLaunch { .. }
                    ) {
                        ensure_kuid_running(
                            &sidecar_states,
                            &surface_proxy_for_kuid,
                            &quitting_for_kuid,
                        )
                        .await;
                    }
                    let resp =
                        match dispatch::handle_request(&ctx, request, caller, conn_session).await {
                            Ok(r) => r,
                            Err(e) => UserResponse::Error {
                                message: e.to_string(),
                            },
                        };
                    Ok(HandlerOutput::Single(resp))
                }
            });
        tokio::select! {
            outcome = accepting => outcome,
            _ = quitting.wait_for(|asked| *asked) => {
                tracing::info!("{}", kotton_common::DAEMON_QUIT_LINE);
                Ok(())
            }
        }
    }

    /// **Stop serving, and let `run` close what this daemon holds.**
    ///
    /// The person chose *Quit Kotton*. `kuid` reported that gesture up the
    /// surface channel it already holds and is leaving; this is kuserd deciding
    /// what the gesture costs, which is the whole of the split between *closing
    /// a window* and *quitting*.
    ///
    /// Returns immediately — the teardown happens where every other teardown
    /// happens. Nothing here ends the process either: `serve` returns to `run`,
    /// `run` returns to `main`, and `main` returning is the exit status the
    /// recipe reads.
    pub fn quit(&self) {
        // Idempotent by construction: the flag is a value, so a second quit
        // says the same thing as the first. A send fails only when nothing is
        // subscribed, which means `serve` never started — there is then nothing
        // to stop, and the daemon is already on its way out.
        let _ = self.quit.send(true);
    }

    // â”€â”€ Peer-listener helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    /// Raw bytes of the device's operational Ed25519 verifying key.
    ///
    /// The remote peer must store this value as `PairedNode.public_key` so that
    /// the mTLS handshake can verify our TLS certificate. The key is persisted
    /// and stable across restarts (`load_or_create_device_signing_key` in
    /// `kotton_device`).
    pub fn device_signing_pubkey_bytes(&self) -> [u8; 32] {
        self.runtime.device_signing_pubkey_bytes()
    }

    /// The DID this node presents to peers — the operational key's — as
    /// `PairedNode.device_did` on the remote peer and the `peer_did` argument
    /// to `remote_add(Kotton { peer_did })` on the connecting side.
    pub fn device_did(&self) -> String {
        self.runtime.operational_did()
    }

    /// Mint a **gateway bootstrap token** for `user_id`, exactly as sidecar spawn
    /// does.
    ///
    /// The resulting token authenticates as `Principal::Gateway`: it may mint a
    /// session for a third party and nothing else (mint-only). Intended for integration
    /// tests that need to exercise the gateway credential without running a real
    /// sidecar process.
    /// The environment `kuserd` would hand `khttpd` at spawn, read from the
    /// device configuration exactly as `supervise_khttpd` reads it.
    ///
    /// For integration tests that start the real `khttpd` binary themselves and
    /// want to prove the stored configuration reaches its socket — the same
    /// hand-over, not a test-only shortcut.
    /// The request-handling context: every shared handle a verb may need, bound
    /// once. Built for the IPC loop and for the peer path alike, so a verb that
    /// arrives over a relayed circuit is dispatched with the same state.
    fn agent_context(&self) -> AgentContext {
        let this = self;
        AgentContext {
            sync_resources: Arc::clone(&this.sync_resources),
            runtime: Arc::clone(&this.runtime),
            endpoint: this.endpoint.clone(),
            users: this.users.clone(),
            record_stores: this.record_stores.clone(),
            db: Arc::clone(&this.db),
            device_db: Arc::clone(&this.device_db),
            user_dbs: Arc::clone(&this.user_dbs),
            event_log_tasks: Arc::clone(&this.event_log_tasks),
            base: this.base.clone(),
            started_at: this.started_at,
            sessions: Arc::clone(&this.sessions),
            gateway_tokens: Arc::clone(&this.gateway_tokens),
            principal_sessions: Arc::clone(&this.principal_sessions),
            paired_keys: Arc::clone(&this.paired_keys),
            sync_engine: Arc::clone(&this.sync_engine),
            live_instances: Arc::clone(&this.live_instances),
            revoked_sessions: Arc::clone(&this.revoked_sessions),
            sidecar_states: Arc::clone(&this.sidecar_states),
            ipc_sessions: Arc::clone(&this.ipc_sessions),
            connected_peers: Arc::clone(&this.connected_peers),
            surface_proxy: Arc::clone(&this.surface_proxy),
            infer_proxy: Arc::clone(&this.infer_proxy),
            window_registry: Arc::clone(&this.window_registry),
            file_reassembly: Arc::clone(&this.file_reassembly),
            runner: this.runner.clone(),
            pending_confirms: Arc::clone(&this.pending_confirms),
            browser_desks: Arc::clone(&this.browser_desks),
            browser_channels: Arc::clone(&this.browser_channels),
            ceremonies: this.ceremonies.clone(),
        }
    }

    pub async fn khttpd_spawn_env(&self) -> io::Result<Vec<(&'static str, String)>> {
        Ok(
            kotton_device::config::ops::web_shell(self.device_db.as_ref())
                .await?
                .spawn_env(),
        )
    }

    pub fn mint_gateway_bootstrap_token(&self, user_id: &str) -> String {
        let token = uuid::Uuid::new_v4().to_string();
        // Process-scoped for the same reason a real sidecar's token is: this
        // stands in for one.
        sessions::insert_process_scoped(&self.sessions, token.clone(), user_id.to_string());
        self.gateway_tokens.write().unwrap().insert(token.clone());
        token
    }

    /// How many live sessions a browser admission minted for `user_id` — a
    /// count, for the suite to see a revoke end the session itself and not only
    /// the channel carrying it. Reads the two maps the channel's calls resolve
    /// through; changes nothing, and hands out no token.
    pub fn live_browser_sessions(&self, user_id: &str) -> usize {
        let principals = self.principal_sessions.read().unwrap();
        principals
            .iter()
            .filter(|(_, p)| matches!(p, kotton_wire::ipc::Principal::Browser { .. }))
            .filter(|(t, _)| sessions::live_user(&self.sessions, t).as_deref() == Some(user_id))
            .count()
    }

    /// Insert a paired-node record directly into the daemon's database.
    ///
    /// Bypasses the full pair handshake.  Intended for integration tests that
    /// need to pre-configure pairing relationships between two in-process
    /// daemon instances.
    pub async fn insert_paired_node(
        &self,
        user_id: &str,
        peer_did: &str,
        pubkey: [u8; 32],
        addr: std::net::SocketAddr,
    ) -> io::Result<()> {
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let id = uuid::Uuid::new_v4().to_string();
        let addresses_json = serde_json::to_string(&[addr]).map_err(io::Error::other)?;
        kotton_peer::daemon::db::insert_paired_node(
            &self.db,
            &id,
            user_id,
            peer_did,
            &pubkey,
            &addresses_json,
            now,
            None,
        )
        .await?;
        // Update the live TLS allowlist so the peer can connect immediately.
        self.paired_keys.write().unwrap().insert(pubkey);
        // A new node may be a vault that should hold this user's doors;
        // the same wake the contact registry listens for.
        self.runtime.contacts_changed().notify_one();
        Ok(())
    }

    /// Every drive this device records for `user_id`
    /// ([`kotton_peer::daemon::drives::all`]): each vault's first drive and
    /// each made beside it. For a caller that holds the daemon — an
    /// integration test that asks what enrolment, recovery, or following a
    /// vault's listing recorded.
    pub async fn drives(&self, user_id: &str) -> io::Result<Vec<kotton_peer::daemon::drives::Drive>> {
        kotton_peer::daemon::drives::all(&self.db, user_id).await
    }

    /// Whether this device holds, here, the content of the file at `path` in
    /// `user_id`'s tree — kept whole by its pins, or fetched since it was
    /// opened (`kotton_store::runtime::user::UserStore::kept_here`). For a
    /// caller that holds the daemon — an integration test that asks what a
    /// pass kept (kotton #55).
    pub async fn kept_here(&self, user_id: &str, path: &str) -> io::Result<bool> {
        let Some(store) = self.users.get(user_id) else {
            return Err(io::Error::other(format!("'{user_id}' is not resident")));
        };
        store.kept_here(path).await.map_err(|e| io::Error::other(format!("{e:#}")))
    }

    /// The user ids this daemon holds an agent-database slot for
    /// (`user_db::UserDbMap`), sorted. For a caller that holds the daemon — an
    /// integration test asking whether a peer's request added one (kotton
    /// #262). Reads the map; opens nothing.
    pub fn agent_db_slots(&self) -> Vec<String> {
        let mut ids: Vec<String> = self.user_dbs.read().unwrap().keys().cloned().collect();
        ids.sort();
        ids
    }

    /// Build the peer-request handler closure.
    ///
    /// The closure decodes each inbound request as a [`PeerRequest`] — the
    /// verbs a paired peer may ask on its own standing, and none of the local
    /// door's — serves it through [`serve_peer_request`], and serializes the
    /// `UserResponse`. A door verb fails at the decoder: it is no request on
    /// this wire (kotton #231).
    fn build_peer_handler(self: &Arc<Self>) -> PeerHandler {
        // What a peer's request is served with on its own standing: one handle
        // per thing a peer verb does, and not the machine. No record store, no
        // sync host, no sync engine, no `DeviceRuntime` among `PeerContext`'s
        // field types (kotton #222, #242); two handles hold the keychain, and
        // what keeps them to their labels is their methods (`PeerContext`'s doc,
        // kotton #256). The guest lookup holds neither it nor the base
        // directory (kotton #262).
        let chains = kotton_device::users::admission::Chains::of(&self.runtime);
        let peer = Arc::new(PeerContext {
            standing: peer_reach::Standing::new(
                Arc::clone(&self.db),
                self.runtime.paired_keys(),
                chains.clone(),
            ),
            // The open map only: a guest lookup reads a database the daemon
            // already opened, and holds nothing one opens from (kotton #262).
            guests: peer_reach::GuestSessions::new(
                Arc::clone(&self.user_dbs),
                Arc::clone(&self.revoked_sessions),
            ),
            stores: file_host::PeerStoreHost::new(
                Arc::clone(self.runtime.event_bus()),
                self.runtime.secrets_arc(),
                self.users.clone(),
            ),
            relay: peer_reach::NodeRelay::new(Arc::clone(self.runtime.reachability())),
            introducer: self.runtime.introducer(),
            recovery: peer_reach::Recovery::new(self.base.clone(), chains),
            db: Arc::clone(&self.db),
            sync_wake: self.sync_engine.waker(),
            // One shared participant for the lifetime of this handler: a
            // distributed-signing round-1 stashes its secret nonces here and
            // the matching round-2 (a later, separate peer request) consumes
            // them. Every listener that clones this handler's Arc shares it.
            signer: peer_reach::FrostSigner::new(
                self.runtime.secrets_arc(),
                Arc::new(kotton_org::frost_signing::FrostParticipant::new()),
            ),
            // Reassembly buffers for chunked sealed writes, shared for the
            // handler's lifetime — a large object's chunks arrive as separate
            // peer requests and accumulate here until complete, the same shape
            // as the FROST participant's cross-request state above.
            sealed_reassembly: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        });
        // A gateway's frames are dispatched as the browser behind it, under the
        // session its admission minted: the person's own verbs, with the whole
        // agent's reach. Held for that path alone ([`handle_gateway_request`]),
        // which only a key the named person pairs as their gateway enters.
        let gateway = Arc::new(self.agent_context());
        Arc::new(move |peer_did: String, req_bytes: Vec<u8>| {
            let peer = Arc::clone(&peer);
            let gateway = Arc::clone(&gateway);
            Box::pin(async move {
                let request = match serde_json::from_slice::<PeerRequest>(&req_bytes) {
                    Ok(r) => r,
                    Err(e) => {
                        return serde_json::to_vec(&UserResponse::Error {
                            message: format!("invalid peer request: {e}"),
                        })
                        .unwrap_or_default();
                    }
                };
                let response = serve_peer_request(&peer, &gateway, &peer_did, request).await;
                serde_json::to_vec(&response).unwrap_or_default()
            }) as std::pin::Pin<Box<dyn std::future::Future<Output = Vec<u8>> + Send>>
        })
    }

    /// Start the QUIC peer listener on `port`.
    ///
    /// The TLS allowlist is the runtime's own — `self.paired_keys` is a handle to
    /// the same set, seeded from the DB at startup and kept live as nodes are
    /// added and revoked.  Builds the request-handler closure capturing the
    /// [`PeerContext`] (and, for a gateway's frames, the agent) and delegates to
    /// [`DeviceRuntime::start_peer_listener`].  The daemon holds the `db` handle;
    /// the runtime crate stays free of a direct SQLite dep.
    pub async fn start_peer_listener_background(self: &Arc<Self>, port: u16) -> anyhow::Result<()> {
        let handler = self.build_peer_handler();
        self.runtime.start_peer_listener(port, handler).await
    }
}

// â”€â”€ Peer request handler â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// What a peer's request is served with on its own standing (kotton #222, #242).
///
/// Every field is something a peer verb uses, and nothing else is here. None is
/// the machine (`DeviceRuntime`): each is a handle with private fields and the
/// methods its verbs ask ([`peer_reach`], [`file_host::PeerStoreHost`]).
///
/// Three things hold three different claims, and they are not the same
/// strength. **The field types** hold that no record store, sync host, sync
/// engine or `DeviceRuntime` is here. **Module privacy** holds that this
/// function's module cannot read a handle's fields. **Method discipline** —
/// what the methods in `peer_reach.rs` and `file_host.rs` choose to do with
/// those fields — holds the rest: two handles (`stores`, `signer`) each hold
/// the whole keychain, `Arc<dyn SecretsStore>`, and that they read only their
/// labels is true of their methods, not of their types (kotton #256).
/// `guests` holds the map of agent databases the daemon already opened and
/// nothing one opens from, so it cannot open, create or migrate a database on
/// a peer's request — held by its field types (kotton #262). The keychain and
/// a base directory, the inputs a record store opens from
/// (`kotton_record::open`), still sit together in one handle: `stores` holds
/// the keychain beside the resident stores, and a resident store answers its
/// base directory (`UserStore::base_dir`). That `stores` opens no record store
/// is its methods' discipline (kotton #256).
///
/// - `standing` — who the peer is to a person: the paired-node rows, the live
///   allowlist, and the identity chains a proof-admitted peer is replayed
///   against (`Chains`: the base directory's chains and the admission table,
///   no keychain).
/// - `guests` — the guest session a stranger's key may hold, found in the
///   person's own database when the daemon already has it open, and the
///   sessions revoked since they were read.
/// - `stores` — the resident object stores, which the file verbs at a path and
///   the sealed-replication verbs read and write, a mount's key domain, and
///   the event bus; each store fetches a pack it does not keep through the
///   `PackSource` the registry lent it.
/// - `relay` — where this node reserves, and what it presents there.
/// - `introducer` — the device's lent handle that opens an introduced
///   listener (`kotton_device::Introducer`).
/// - `recovery` — a person's public chain and phrase-sealed copy.
/// - `db` — the paired-node rows a posture is read from.
/// - `sync_wake` — the two wakes: it starts a pass sooner, and reaches nothing
///   a pass reaches.
/// - `signer` — this node's FROST share for a person, answering one round, and
///   the nonces a round keeps between requests.
/// - `sealed_reassembly` — the state a chunked sealed write keeps between
///   requests.
///
/// **What is not here, by type:** the machine; the record stores, the sync
/// host that opens them, the sync engine, the sessions and every other field
/// of [`AgentContext`]; and, in `guests`, anything an agent database opens
/// from (kotton #262). The keychain is still whole inside `stores` and
/// `signer`, and `stores` reaches a base directory through the resident stores
/// (kotton #256).
pub(super) struct PeerContext {
    standing: peer_reach::Standing,
    guests: peer_reach::GuestSessions,
    stores: file_host::PeerStoreHost,
    relay: peer_reach::NodeRelay,
    introducer: kotton_device::Introducer,
    recovery: peer_reach::Recovery,
    db: Arc<SqlitePool>,
    sync_wake: kotton_sync::engine::SyncWake,
    signer: peer_reach::FrostSigner,
    sealed_reassembly: kotton_device::users::files::SealedReassembly,
}

/// Serve one peer request: decide who it is for and what the key is to that
/// person ([`peer_ask`]), then hand it to the one path that answers it.
///
/// Two paths, by what the person's row says the key is, and two contexts:
/// a gateway's request goes to [`handle_gateway_request`] with the agent, and
/// every other to [`handle_peer_request`] with [`PeerContext`] alone. The
/// agent is passed through here and nowhere below the person's path.
async fn serve_peer_request(
    peer: &PeerContext,
    gateway: &AgentContext,
    peer_did: &str,
    request: PeerRequest,
) -> UserResponse {
    use kotton_crypto::did::DidKeyMethod;
    use kotton_wire::did::Did;
    let peer_pubkey_bytes: Option<[u8; 32]> = Did::parse(peer_did)
        .ok()
        .and_then(|d| DidKeyMethod::to_public_key(&d).ok())
        .map(|vk| vk.to_bytes());

    // A gateway device is paired so the relay carries it and the handshake
    // admits it; its *posture* is what keeps pairing from being reach. It
    // speaks one verb of a person's, for the person whose row pairs it as
    // their gateway, and the frames it carries are dispatched as that
    // person's browser — so this is decided, for the person the request
    // names, before the person's path can treat it as a device.
    match peer_ask(&peer.db, peer_pubkey_bytes.as_ref(), &request).await {
        Ok(PeerAsk::Person(user_id)) => {
            handle_peer_request(peer, peer_did, peer_pubkey_bytes, user_id, request).await
        }
        Ok(PeerAsk::Gateway(gateway_user)) => {
            handle_gateway_request(gateway, peer_did, gateway_user.as_str(), request).await
        }
        Err(message) => UserResponse::Error { message },
    }
}

/// A request from a key that `gateway_user`'s row pairs as their gateway.
///
/// **This path's reach is the person's own, through their browser, and it is
/// the whole agent.** A gateway speaks one verb, `BrowserFrame`, and may ask
/// `NodeRelay` — where this node reserves, nothing of the person's. A frame is
/// ciphertext the gateway cannot open: the pairing ceremony runs over the
/// first frames (a browser this node has never seen waits for the person at
/// their desk), and once it establishes, each frame carries one of the
/// person's own door verbs — `RecordInsert` and `RecordQuery` among them —
/// which `browser_channel` dispatches through the local door's
/// `dispatch::handle_request` under the browser's session minted at that
/// admission, at `Paired` origin, against the same guard every caller faces.
/// So the agent, record stores included, is reachable from here: not by the
/// gateway on its own standing, which asks nothing but frames, but by the
/// person's browser, which is the person. Narrowing what a browser's session
/// may reach is that session's scope, not this path's type, and is not done
/// here (kotton #222 stays open for it).
async fn handle_gateway_request(
    agent: &AgentContext,
    peer_did: &str,
    gateway_user: &str,
    request: PeerRequest,
) -> UserResponse {
    match request {
        PeerRequest::BrowserFrame { bytes, channel, .. } => {
            browser_channel::handle_gateway_frame(agent, peer_did, gateway_user, channel, bytes).await
        }
        PeerRequest::NodeRelay { .. } => UserResponse::NodeRelayResult {
            relay_url: Some(agent.runtime.reachability().nat().relay_url).filter(|u| !u.is_empty()),
            relay_key: agent.runtime.reachability().nat().relay_key,
            // A gateway is not one of the person's devices, and is
            // handed no relay's key.
            admission: None,
        },
        other => UserResponse::Error {
            message: format!(
                "a gateway speaks one verb, BrowserFrame, and may ask NodeRelay; {} is refused",
                other.variant_name()
            ),
        },
    }
}

/// Who a peer's request is for, and what the peer is to that person — read
/// from **that person's** row for the key the handshake proved
/// ([`peer_ask`]).
#[derive(Debug, PartialEq, Eq)]
enum PeerAsk {
    /// The person's row pairs the key as their gateway (`Posture::Gateway`):
    /// for them it speaks a gateway's one verb, `BrowserFrame`, and may ask
    /// `NodeRelay`, and the frames it carries are their browser's.
    Gateway(UserId),
    /// Anything else the key is to the person — their device, a vault, a
    /// stranger — which `peer_standing` classifies next.
    Person(UserId),
}

/// The person a peer's request names, and whether the key that sent it is
/// that person's gateway: the peer path's one decision about a gateway, made
/// for a person and never across persons.
///
/// The handshake proves a key and nothing else, and rows are each person's
/// (`kotton_peer::daemon::db`), so one key may be one person's gateway and
/// another's device, or two people's gateway. Every verb a peer may ask names
/// its person — `BrowserFrame` too, in its `user_id` — and that person's
/// posture for the key decides what the key is *to them*
/// (`paired_posture_for_user`). The name selects among the reach the key's own
/// rows grant and adds none: a frame naming a person who does not pair the
/// key as their gateway is refused, and another verb naming a person whose
/// row says gateway is held to the gateway's verbs.
///
/// A `BrowserFrame` naming no one is refused, never resolved to the one person
/// who pairs the key as a gateway: that fallback is the person-less read
/// kotton #119 removes, narrowed to the unambiguous case. So a relayed gateway
/// that does not yet send `user_id` is refused on every frame, naming the
/// field, until it does (kotton-ahead#339); the local path never comes here.
///
/// `Err` is the refusal to send back.
async fn peer_ask(
    db: &Arc<SqlitePool>,
    pk: Option<&[u8; 32]>,
    request: &PeerRequest,
) -> Result<PeerAsk, String> {
    let user_id = match request {
        PeerRequest::ReadFile { user_id, .. }
        | PeerRequest::WriteFile { user_id, .. }
        | PeerRequest::ListFiles { user_id, .. }
        | PeerRequest::DeleteFile { user_id, .. }
        | PeerRequest::SyncAvailable { user_id, .. }
        | PeerRequest::RecordSyncAvailable { user_id, .. }
        | PeerRequest::FrostSignRound { user_id, .. }
        | PeerRequest::ReadSealed { user_id, .. }
        | PeerRequest::ListSealed { user_id, .. }
        | PeerRequest::WriteSealed { user_id, .. }
        | PeerRequest::RecoveryFetch { user_id }
        | PeerRequest::RecoveryStore { user_id, .. }
        | PeerRequest::NodeRelay { user_id }
        | PeerRequest::Introduce { user_id, .. }
        | PeerRequest::BrowserFrame { user_id: Some(user_id), .. } => user_id.as_str(),
        PeerRequest::BrowserFrame { user_id: None, .. } => {
            return Err("a gateway's BrowserFrame over a peer connection names the person it is for \
                        (`user_id`); this one names no one"
                .to_string())
        }
    };
    // The one parse of the name the request carries: everything below — a
    // row, a chain, a database, a keychain label, a path — is reached with a
    // `UserId`, never the wire's string (kotton #262).
    let user_id = UserId::parse(user_id)
        .map_err(|e| format!("the request names {user_id:?}, which is not a user id: {e}"))?;
    let gateway = match pk {
        Some(pk) => kotton_peer::daemon::db::paired_posture_for_user(db, pk, user_id.as_str())
            .await
            .map_err(|e| format!("authorization check failed: {e}"))?
            .flatten()
            .is_some_and(|p| p == kotton_schemas::membership::Posture::Gateway.as_str()),
        None => false,
    };
    if gateway {
        return Ok(PeerAsk::Gateway(user_id));
    }
    if matches!(request, PeerRequest::BrowserFrame { .. }) {
        return Err(format!(
            "BrowserFrame over a peer connection is the verb of a gateway '{user_id}' pairs, \
             and '{user_id}' does not pair this key as one"
        ));
    }
    Ok(PeerAsk::Person(user_id))
}

/// Whether the peer asking `NodeRelay` for `user_id` is one of that person's
/// own devices that holds their keys (`Posture::Full`, or a row from before
/// postures), and so is handed what this node presents at its relay. Read
/// from **this person's** row for the key, not any person's: rows are each
/// person's (`kotton_peer::daemon::db`), and another person's row for the same
/// key says nothing of what it is to this one. Unreadable reads as no.
async fn asks_as_own_device(db: &Arc<SqlitePool>, pk: &[u8; 32], user_id: &str) -> bool {
    match kotton_peer::daemon::db::paired_posture_for_user(db, pk, user_id).await {
        Ok(Some(None)) => true,
        Ok(Some(Some(p))) => p == kotton_schemas::membership::Posture::Full.as_str(),
        _ => false,
    }
}

/// Serve one request a peer asks on its own standing, for `user_id`, from a key
/// the TLS handshake verified and [`peer_ask`] found is not that person's
/// gateway.
///
/// `peer_did` is the connecting device's `did:key:…` string, extracted from its
/// TLS certificate.  Before serving any request we verify that `peer_did` is
/// either permanently paired with the `user_id` named in the request, or holds
/// an active (non-revoked, non-expired) `EphemeralSession` scoped to that user.
/// For ephemeral sessions, path-level grant enforcement is also applied.
///
/// **What a request can reach from here is [`PeerContext`], and that is all.**
/// The request is a [`PeerRequest`], so no door verb arrives (kotton #231); the
/// context holds no record store, no sync host and no sync engine (kotton
/// #222); and it holds no `DeviceRuntime` (kotton #242). Those three are held
/// by [`PeerContext`]'s field types.
///
/// The person the request names arrives as a [`UserId`], parsed once in
/// [`peer_ask`]: a name that is not a user id (`..`, `/`, empty, over-long) is
/// refused there, before any row, chain, path or keychain label is built from
/// it, and every arm below uses the parsed id, not the variant's own string
/// (kotton #262). The request type still carries a `String`; whether the wire
/// should carry the parsed type is #262's open half.
///
/// **The guest lookup cannot open a database, and that is held by type.**
/// [`peer_reach::GuestSessions`] holds only the map of agent databases the
/// daemon already opened and the revoked set — no base directory, no keychain
/// — so on a stranger's request this node opens, creates, migrates and
/// remembers nothing for the name it gives, and reads no secret for it
/// (kotton #262). [`peer_reach::Recovery`] holds the base directory and no
/// keychain.
///
/// **Reach to a record store is not yet absent; it is held by method
/// discipline**, in one handle now rather than two: [`file_host::PeerStoreHost`]
/// holds the whole keychain beside the resident stores, and a resident store
/// answers its base directory (`UserStore::base_dir`) — together, what
/// `kotton_record::open` takes. The keychain itself is whole in two handles
/// (`PeerStoreHost`, [`peer_reach::FrostSigner`]), each reading only its
/// labels because its methods do. Lending each only its labels, and no handle
/// a base directory beside them, is kotton #256. What remains, and what holds
/// each:
///
/// - the person's resident **object stores**, at a path for a paired device or
///   a guest within its grant, and as sealed objects for a paired device —
///   through [`file_host::PeerStoreHost`], a `StoreHost` with no sync host and
///   no machine behind it. A resident store fetches a pack it does not keep
///   from the person's drives when it is read (kotton #55) through the
///   `PackSource` the registry lent it, whose one verb is fetching a sealed
///   pack by key (the sync host's absence is held by type). The host holds the
///   whole keychain, and its methods read and write `sealed_mount_domain` (a
///   mount's pinned key domain) and read `operational_cek` (the CEK whose
///   domain this node advertises when the person's store is not resident) —
///   and, when no CEK is stored, **the person's root seed** (`seed32`), which
///   `resolve_operational_cek` falls back to and derives the CEK from. So a
///   peer's file or sealed request can make this host read a root secret
///   (method discipline);
/// - this node's **FROST share** for the person, read by
///   [`peer_reach::FrostSigner`] under its one label to answer a round, and
///   never handed out — the signer holds the whole keychain, and its method is
///   what reads one label (method discipline);
/// - the person's **database**, when the daemon already has it open, for the
///   one question of which guest session a stranger's key holds — read by
///   [`peer_reach::GuestSessions`] from the open map, never opened by it; a
///   database not open reads as no session, and the pool is not handed out
///   (held by type: the handle holds nothing a database opens from);
/// - the **identity chains** and the admission table (`Chains`), to classify
///   the peer and to keep a delivered recovery copy's events, and the
///   phrase-sealed copy itself ([`peer_reach::Recovery`]);
/// - the machine's **relay** configuration and keyring
///   ([`peer_reach::NodeRelay`]), and its **introductions**
///   (`kotton_device::Introducer`): the listeners open now and the device key
///   they present;
/// - the paired-node rows.
///
/// **Records do not arrive here as rows.** The record log over sealed segments
/// is the one path a record takes between devices: the sync engine seals
/// changes with `kotton_record::replication::log_records`, the pack moves like
/// any other, and `apply_record_segments` merges what it carries on the far
/// side. A peer's only record verb on its own standing is
/// `RecordSyncAvailable`, which wakes that pass and carries no record; a
/// gateway's frame carries the person's own verbs under the browser's session,
/// and is [`handle_gateway_request`]'s, not this function's. The verb that let
/// a paired peer hand this device plaintext rows to merge
/// (`ApplyRecordChangeset`) is retired (kotton #173).
async fn handle_peer_request(
    peer: &PeerContext,
    peer_did: &str,
    peer_pubkey_bytes: Option<[u8; 32]>,
    user_id: UserId,
    request: PeerRequest,
) -> UserResponse {
    let PeerContext {
        standing: standing_of,
        guests,
        stores,
        relay,
        introducer,
        recovery,
        db,
        sync_wake,
        signer,
        sealed_reassembly,
    } = peer;

    // Who is this peer to this user? Paired, admitted on proof (and written
    // down here, on its first request), admitted on a recovery claim, or none
    // of those. The classification is the device crate's — a vault makes the
    // same call — and what follows a `Stranger` is this daemon's alone: a
    // guest session, which a vault never grants.
    let standing = match standing_of.of(peer_did, peer_pubkey_bytes, &user_id).await {
        Ok(s) => s,
        Err(e) => {
            return UserResponse::Error {
                message: format!("authorization check failed: {e}"),
            }
        }
    };
    use kotton_device::users::admission::PeerStanding;
    let paired = matches!(standing, PeerStanding::Paired);
    let claim_for: Option<String> = match &standing {
        PeerStanding::Claim { aid } => Some(aid.clone()),
        _ => None,
    };
    if let (Some(aid), false) = (&claim_for, paired) {
        if !matches!(request, PeerRequest::RecoveryFetch { .. })
            || standing_of.aid_of(&user_id).as_deref() != Some(aid.as_str())
        {
            return UserResponse::Error {
                message: "a device admitted on a recovery claim may only fetch the identity \
                          it claimed"
                    .to_string(),
            };
        }
    }

    if !paired && claim_for.is_none() {
        // Not in paired_nodes â€” check for a valid ephemeral session.
        use kotton_schemas::{CapabilityKind, CapabilitySet, CapabilityTarget};
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);

        // Guest sessions live in the target user's database (3b-v), read only
        // when the daemon already has it open: a database not open reads as
        // "no session", the same refusal shape, and nothing is opened, created
        // or remembered for the name on this peer's standing (kotton #262).
        let session_lookup = guests.find(peer_did, &user_id).await;
        match session_lookup {
            Ok(Some(session)) => {
                // In-memory revocation check (fast path â€” DB query already filters revoked=0,
                // but the in-memory set avoids a second DB lookup race).
                if guests.revoked(&session.id) {
                    tracing::warn!(
                        peer_did = %peer_did,
                        session_id = %session.id,
                        "peer ephemeral session is revoked (in-memory set)"
                    );
                    return UserResponse::Error {
                        message: "ephemeral session revoked".to_string(),
                    };
                }

                // Issuer signature verification.
                if !kotton_grant::daemon::grants::verify_envelope_signature(&session.grant) {
                    tracing::warn!(
                        peer_did = %peer_did,
                        session_id = %session.id,
                        "peer ephemeral session has invalid issuer signature"
                    );
                    return UserResponse::Error {
                        message: "invalid guest token signature".to_string(),
                    };
                }

                // Expiry check.
                if let Some(exp) = session.grant.expires_at {
                    if now > exp {
                        tracing::warn!(
                            peer_did = %peer_did,
                            "peer ephemeral session has expired"
                        );
                        return UserResponse::Error {
                            message: "ephemeral session expired".to_string(),
                        };
                    }
                }

                // Path-level grant check: the requested path must be covered by
                // a Vfs grant with the appropriate kind.
                let (req_path, req_kind): (&str, CapabilityKind) = match &request {
                    PeerRequest::ReadFile { path, .. }
                    | PeerRequest::ListFiles { prefix: path, .. } => {
                        (path.as_str(), CapabilityKind::Read)
                    }
                    PeerRequest::WriteFile { path, .. } | PeerRequest::DeleteFile { path, .. } => {
                        (path.as_str(), CapabilityKind::Write)
                    }
                    // Sync notification and record-push operations require a
                    // permanent pairing, not an ephemeral guest session.
                    _ => {
                        return UserResponse::Error {
                            message: "sync operations require a paired connection".to_string(),
                        };
                    }
                };

                // Enforce path scoping through the hardened `CapabilitySet::allows`
                // (normalizes `.`/`..` and requires a `/` boundary), not a raw
                // `starts_with`. A raw prefix check let `/shared` admit
                // `/shared/../../etc/identity` (traversal) and `/shared-private`
                // (sibling prefix) — a network-facing confinement break (audit H3).
                let requested = CapabilityTarget::Vfs {
                    path: req_path.to_string(),
                };
                if !CapabilitySet::new(session.grant.grants.clone()).allows(&req_kind, &requested) {
                    tracing::warn!(
                        peer_did = %peer_did,
                        req_path = %req_path,
                        "peer ephemeral session does not cover this path/operation"
                    );
                    return UserResponse::Error {
                        message: "ephemeral session does not grant access to this path".to_string(),
                    };
                }
            }
            Ok(None) => {
                tracing::warn!(
                    peer_did = %peer_did,
                    user_id = %user_id,
                    "peer attempted to access user data but is not paired to that user"
                );
                return UserResponse::Error {
                    message: "peer not authorized for this user".to_string(),
                };
            }
            Err(e) => {
                return UserResponse::Error {
                    message: format!("authorization check failed: {e}"),
                };
            }
        }
    }

    // Sealed replication is an **own-device** operation and is refused to an
    // ephemeral guest even when its grant covers the path. `ReadSealed` hands back
    // the raw envelope rather than the path-scoped plaintext a guest is entitled
    // to, and `WriteSealed` writes bytes that bypass sealing entirely — neither
    // belongs to a principal holding only a path-scoped grant. Permanent pairing
    // is the check: `paired_nodes` is populated by device enrollment, so a peer
    // that clears it is one of the user's own devices.
    if !paired
        && claim_for.is_none()
        && matches!(
            request,
            PeerRequest::ReadSealed { .. }
                | PeerRequest::ListSealed { .. }
                | PeerRequest::WriteSealed { .. }
                | PeerRequest::RecoveryFetch { .. }
                | PeerRequest::RecoveryStore { .. }
        )
    {
        tracing::warn!(
            peer_did = %peer_did,
            user_id = %user_id,
            "ephemeral guest attempted sealed replication"
        );
        return UserResponse::Error {
            message: "sealed replication requires a paired device".to_string(),
        };
    }

    let _caller = if paired {
        CallerContext::PairedDevice {
            peer_did: peer_did.to_string(),
        }
    } else {
        CallerContext::EphemeralGuest {
            peer_did: peer_did.to_string(),
        }
    };

    // Each variant's own `user_id` is the string `peer_ask` parsed; the arms
    // use the parsed `user_id` and bind the string to nothing (kotton #262).
    let result: io::Result<UserResponse> = match request {
        PeerRequest::ReadFile {
            user_id: _,
            path,
            offset,
            length,
        } => {
            kotton_device::users::files::read_file(
                stores,
                user_id.to_string(),
                path,
                offset,
                length,
            )
            .await
        }
        PeerRequest::WriteFile {
            user_id: _,
            path,
            data,
            offset,
            total_size,
            content_hash,
        } => {
            kotton_device::users::files::write_file(
                stores,
                user_id.to_string(),
                path,
                data,
                offset,
                total_size,
                content_hash,
                Some(sealed_reassembly),
            )
            .await
        }
        PeerRequest::ListFiles { user_id: _, prefix } => {
            kotton_device::users::files::list_files(
                stores,
                user_id.to_string(),
                prefix,
            )
            .await
        }
        PeerRequest::DeleteFile { user_id: _, path } => {
            kotton_device::users::files::delete_file(
                stores,
                user_id.to_string(),
                path,
            )
            .await
        }

        // -- Where this node reserves ----------------------------------------
        // Asked by every paired peer after a connect, so a relay change follows
        // the pair. One URL of this node's own configuration, nothing of the
        // user's; a peer that is not paired never reaches this arm.
        // And the key this node presents there, when it holds one: the asker
        // is one of the same person's own devices (every other standing was
        // refused above), so it is handed what this one presents — and, on the
        // relay's operator's own devices, the invited key their reach note
        // offers on: a device presents its relay's admission tag, and the reach
        // row sets the rule.
        //
        // Only to a device that holds the person's keys (`Posture::Full`, or a
        // row from before postures, which is one): a cosigner or blind storage
        // is paired to this person and may be a host's machine, so it is told
        // where this node reserves and handed no key of the person's.
        PeerRequest::NodeRelay { .. } => {
            let own_device = match peer_pubkey_bytes {
                Some(pk) => asks_as_own_device(db, &pk, user_id.as_str()).await,
                None => false,
            };
            Ok(relay.answer(&user_id, own_device))
        }

        // -- A relay introduces your devices ---------------------------------
        // One of the person's own devices (a claim, a guest and a gateway are each
        // refused above: a claim may only fetch, a guest's path-grant check answers
        // every verb but the four file verbs with a refusal, and a gateway speaks two
        // verbs) asks for a listener that hears its address and its token
        // and nothing else, for one session. The ask arrived over a sealed channel;
        // the answer goes back over it, and the relay carried both unread.
        PeerRequest::Introduce { addr, token, router, .. } => {
            let (Some(peer_key), Ok(addr), Some(token)) = (
                peer_pubkey_bytes,
                addr.parse::<std::net::SocketAddr>(),
                kotton_peer::introduction::parse_token(token.expose()),
            ) else {
                return UserResponse::Error {
                    message: "an introduction names an ip:port and a 16-byte token".to_string(),
                };
            };
            match introducer
                .open(
                    peer_key,
                    kotton_net::transport::quic::introduced::IntroducedPeer { addr, token },
                    router.as_deref().and_then(kotton_peer::local_door::RouterKey::from_hex),
                    kotton_peer::introduction::TOKEN_LIFETIME,
                )
                .await
            {
                Ok(at) => Ok(UserResponse::Introduced {
                    addr: at.to_string(),
                }),
                Err(e) => Ok(UserResponse::Error {
                    message: format!("no introduction: {e}"),
                }),
            }
        }

        // -- Recovery ---------------------------------------------------------
        // Reached by a paired device, or by one admitted on a recovery claim for
        // exactly this identity (checked above). Serves the public chain and the
        // phrase-sealed copy verbatim; this node can open neither.
        PeerRequest::RecoveryFetch { .. } => Ok(recovery.fetch(&user_id)),
        // A paired device delivers the phrase-sealed copy after the fact. Only a
        // *paired* device reaches here (a claim-admitted one is refused above),
        // and the node keeps the bytes it cannot open, exactly as at enrolment.
        PeerRequest::RecoveryStore {
            user_id: _,
            bundle,
            kel,
        } => {
            if claim_for.is_some() {
                return UserResponse::Error {
                    message: "a device admitted on a recovery claim may not store a copy"
                        .to_string(),
                };
            }
            Ok(recovery.store(peer_did, &user_id, &bundle, &kel))
        }

        // -- Sealed replication -----------------------------------------------
        PeerRequest::ReadSealed {
            user_id: _,
            mount,
            path,
            offset,
            length,
        } => {
            kotton_device::users::files::read_sealed(
                stores,
                user_id.to_string(),
                mount,
                path,
                offset,
                length,
            )
            .await
        }
        PeerRequest::ListSealed {
            user_id: _,
            mount,
            prefix,
        } => {
            kotton_device::users::files::list_sealed(
                stores,
                user_id.to_string(),
                mount,
                prefix,
            )
            .await
        }
        PeerRequest::WriteSealed {
            user_id: _,
            mount,
            path,
            blob,
            domain_id,
            offset,
            total_size,
            content_hash,
        } => {
            kotton_device::users::files::write_sealed(
                stores,
                user_id.to_string(),
                mount,
                path,
                blob,
                domain_id,
                offset,
                total_size,
                content_hash,
                Some(sealed_reassembly),
            )
            .await
        }

        // -- Device sync notifications ----------------------------------------
        PeerRequest::SyncAvailable { paths, .. } => {
            tracing::debug!(
                peer_did = %peer_did,
                user_id = %user_id,
                paths = ?paths,
                "sync_engine: peer pushed file changes â€” waking local sync pass"
            );
            sync_wake.wake();
            Ok(UserResponse::SyncAck)
        }

        PeerRequest::RecordSyncAvailable { nsids, .. } => {
            tracing::debug!(
                peer_did = %peer_did,
                user_id = %user_id,
                nsids = ?nsids,
                "sync_engine: peer pushed record changes â€” waking local record sync pass"
            );
            sync_wake.wake();
            Ok(UserResponse::SyncAck)
        }

        // -- Distributed FROST signing — co-signer side -----------------------
        // Only reachable when the caller is a permanently paired node (the
        // ephemeral path above rejects non-file ops). The signer loads this
        // node's FROST share and answers one round; its participant holds the
        // round-1 nonces between this request and the next. The share never
        // leaves the signer.
        PeerRequest::FrostSignRound { payload, .. } => Ok(signer.answer(&user_id, &payload)),

        // A frame is a gateway's verb: `peer_ask` sent each one to the
        // gateway's path or back refused, before this function was entered.
        // Named here because the type has the variant, not because a frame can
        // arrive; the catch-all that stood here answered every door verb.
        PeerRequest::BrowserFrame { .. } => Ok(UserResponse::Error {
            message: "BrowserFrame over a peer connection is a gateway's verb".to_string(),
        }),
    };
    result.unwrap_or_else(|e| UserResponse::Error {
        message: e.to_string(),
    })
}

// â”€â”€ Bundled app auto-install â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Locate a sidecar binary sitting next to the running `kuserd` executable.
///
/// Appends `.exe` on Windows so that `CreateProcess` can find the binary when
/// a full path is supplied (Windows does not auto-append extensions for fully
/// qualified paths the way PATH lookup does).
fn sidecar_bin(name: &str) -> std::path::PathBuf {
    let with_ext = format!("{name}{}", std::env::consts::EXE_SUFFIX);
    match std::env::current_exe() {
        Ok(p) => p
            .parent()
            .map(|d| d.join(&with_ext))
            .unwrap_or_else(|| std::path::PathBuf::from(&with_ext)),
        Err(_) => std::path::PathBuf::from(&with_ext),
    }
}

/// Install any bundled first-party app that is not yet in the `app_registry`.
///
/// Called once at daemon startup via `new_with_base`.  Errors are logged but
/// do not abort startup â€” a broken bundled app should not prevent the daemon
/// from serving other requests.
/// Give `user_id` their own event log, chained under their key when it is
/// resolvable, and register the task so logout can stop it.
///
/// One log per loaded principal — not one log for "the principal", which is
/// what an earlier pass did by taking `loaded_users.first()`. The event bus is
/// device-wide, so that arrangement wrote *every* user's events into the first
/// user's database, sealed under the first user's HMAC chain: a cross-principal
/// write, and the defect class per-user daemons exist to remove. Attribution rides
/// on the event itself ([`EventScope`]) and each log takes only its own.
///
/// Called at boot for every resident account and again by
/// [`custody_window::rekey_resident_store`] when a credential reopens one, since a
/// lock stops the task: an account's event log lives by the lock, not by the process.
/// A second call while this account's task is live does nothing: two logs would
/// write every event twice, and replacing the handle would detach a task that
/// still owns a pool clone.
async fn spawn_user_event_log(
    runtime: &DeviceRuntime,
    user_dbs: &crate::db::user_db::UserDbMap,
    base: &Path,
    tasks: &crate::event_log::EventLogTasks,
    user_id: &str,
) {
    if tasks
        .lock()
        .unwrap()
        .get(user_id)
        .is_some_and(|handle| !handle.is_finished())
    {
        return;
    }
    match crate::db::user_db::user_agent_db(
        user_dbs,
        base,
        runtime.secrets(),
        user_id,
        &runtime.schema_registry,
    )
    .await
    {
        Ok(pool) => {
            // A master secret the store could not read starts no log, as an
            // `agent.db` that would not open starts none — never a log chained
            // under no key, or under a key derived from another root.
            let hmac_key = match crate::db::user_db::resolve_master(runtime.secrets(), user_id) {
                Ok(master) => master.map(|m| {
                    kotton_crypto::derive_db_key(&m, kotton_common::crypto::kdf_labels::HMAC_EVENTS)
                }),
                Err(e) => {
                    eprintln!("[daemon] warning: event log unavailable for '{user_id}': {e}");
                    return;
                }
            };
            let receiver = runtime.event_bus().subscribe();
            let handle = spawn_subscriber_task(
                Arc::new(SqliteEventLog::from_pool(
                    (*pool).clone(),
                    hmac_key,
                    EventScope::User(user_id.to_string()),
                )),
                receiver,
            );
            // Keeping the handle is not bookkeeping: the task owns a clone of
            // this user's pool, so an unheld handle is a file this daemon can
            // never close.
            tasks.lock().unwrap().insert(user_id.to_string(), handle);
        }
        Err(e) => eprintln!("[daemon] warning: event log unavailable for '{user_id}': {e}"),
    }
}

/// The device's own log: everything not attributable to a principal — boot,
/// transport, discovery, pairing. It writes to the machine-wide `agent.db`,
/// which no user's key chains and which `kotton events` already reads.
///
/// Returns the task handle for the same reason [`spawn_user_event_log`] keeps
/// one: the task owns a clone of the machine pool, so an unheld handle is a pool
/// this daemon can never close. Dropping it here is what let the device log keep
/// writing into `agent.db` after shutdown had closed it — two "attempted to
/// acquire a connection on a closed pool" warnings on every stop.
fn spawn_device_event_log(runtime: &DeviceRuntime, db: &SqlitePool) -> JoinHandle<()> {
    let receiver = runtime.event_bus().subscribe();
    spawn_subscriber_task(
        Arc::new(SqliteEventLog::from_pool(
            db.clone(),
            None,
            EventScope::Device,
        )),
        receiver,
    )
}

async fn auto_install_bundled_apps(
    user_db: &Arc<SqlitePool>,
    base: &Path,
    // Whose database this is.
    //
    // Never `""`, on the reasoning that a bundled app is installed "at boot time" with nobody
    // present. That is true of a boot pass and is not true here: this runs on a *user
    // database open*, so the user exists, their KEL is on disk and their signing key is
    // reachable. The empty string takes the `identity key not available; skipping
    // GrantEnvelope` arm and leaves every bundled install unsigned.
    user_id: &str,
    secrets: &dyn SecretsStore,
) {
    for app in bundled_apps() {
        // Parse just enough of the manifest to get the app_id.
        let app_id = match AppManifest::from_toml(app.manifest_toml) {
            Ok(m) => m.app.id.as_str().to_owned(),
            Err(e) => {
                eprintln!("[bundled] failed to parse manifest: {e}");
                continue;
            }
        };

        // Compute BLAKE3 of the embedded WASM bytes — the same hash
        // `kotton_app::daemon::apps::app_install` stores as `wasm_hash`. A
        // SHA-256 of the bytes would never match the stored BLAKE3 digest, so the
        // skip below would be dead and every bundled app rewritten on every
        // call, at every boot — invisible, because a rewrite with identical bytes
        // looks like nothing happened. The unlock caller's test asserts an
        // already-current app's `installed_at` does not move.
        let current_hash = blake3::hash(app.wasm_bytes).to_hex().to_string();

        // Check stored hash â€” if it matches, skip reinstall.
        let stored_hash = app_registry_db::get_wasm_hash(user_db, &app_id)
            .await
            .unwrap_or(None);

        // A row from before the approval column existed has no recorded
        // approval, and an app with no recorded approval now launches with no
        // capabilities at all: the approval is enforced, not only signed.
        // For a bundled app that is repairable without asking anyone: the system
        // approved these when it compiled them in, so reinstall to write that
        // down. Without this, upgrading would leave the shell running and unable
        // to reach the user's files, which is a failure mode that looks like a
        // bug rather than a security posture.
        let has_approval = app_registry_db::get_approved(user_db, &app_id)
            .await
            .unwrap_or(None)
            .is_some();

        if stored_hash.as_deref() == Some(current_hash.as_str()) && has_approval {
            tracing::debug!(%app_id, "bundled app up to date, skipping reinstall");
            continue;
        }

        if !has_approval && stored_hash.is_some() {
            println!("[bundled] recording the system approval for {app_id}…");
        }

        if stored_hash.is_some() {
            println!("[bundled] WASM changed for {app_id}, reinstallingâ€¦");
        }

        match kotton_app::daemon::apps::app_install(
            user_db,
            base,
            user_id,
            app.manifest_toml.to_owned(),
            app.wasm_bytes.to_vec(),
            None,
            secrets,
            // Compiled into this binary and installed at boot with nobody at the
            // keyboard. Named rather than defaulted so the absence of a human is
            // visible here: no user key exists yet at this point, so no envelope
            // is signed either — a bundled app runs on its declared set until a
            // user approves it.
            kotton_schemas::ApprovedCapabilities::system_bundled(bundled_manifest_capabilities(
                app.manifest_toml,
            )),
        )
        .await
        {
            Ok(_) => println!("[bundled] installed {app_id}"),
            Err(e) => eprintln!("[bundled] failed to install {app_id}: {e:?}"),
        }
    }
}
// â"€â"€ ksyncd supervision â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

/// Stop supervising `name` and say why — once, at error, and on the readout
/// `kotton sidecars` gives. See [`liveness`].
fn give_up(
    name: &str,
    sidecar_states: &Arc<RwLock<HashMap<String, SidecarState>>>,
    reason: String,
) {
    tracing::error!(sidecar = name, "{name} {reason}");
    if let Some(state) = sidecar_states.write().unwrap().get_mut(name) {
        state.running = false;
        state.pid = None;
        state.failed = Some(reason);
    }
}

/// Record why a supervised process last ended, without ending supervision.
///
/// The counterpart to [`give_up`]: that one is the terminal case and this one
/// is the ordinary one — a sidecar that exited non-zero and is about to be
/// restarted. Written to the log and nowhere else, `kotton sidecars` would show
/// the restart count rising with no cause beside it, and a person could not tell
/// a crash from a refused frame from a machine under load.
///
/// `running` and `pid` are not touched: the caller has already cleared them,
/// and this says what happened rather than what is happening.
fn note_failure(
    name: &str,
    sidecar_states: &Arc<RwLock<HashMap<String, SidecarState>>>,
    reason: String,
) {
    tracing::warn!(sidecar = name, "{name} {reason}");
    if let Some(state) = sidecar_states.write().unwrap().get_mut(name) {
        state.failed = Some(reason);
    }
}

/// How much of a sidecar's last stderr line is kept as the reason.
///
/// Bounded because the line comes from the process on the other side of a
/// containment boundary. `kinferd` parses weights an attacker may have written,
/// so its diagnostics are attacker-influenced in the limit, and
/// this string is shown to a person by `kotton sidecars` and held in the
/// daemon's memory. A refusal names a length or a decoder's complaint and fits
/// easily; anything longer is a process that has stopped explaining itself.
///
/// It counts **characters of the child's line as the child wrote it**, which for
/// a `tracing` sidecar includes that line's own timestamp and level — about
/// forty of the 512. `note_failure` then prefixes the sidecar's name when it
/// logs, so the daemon's log line carries two prefixes and the recorded reason
/// carries one. Stated rather than trimmed: parsing a child's log format to
/// strip it would be this end deciding what the other end's diagnostics mean.
const STDERR_REASON_MAX: usize = 512;

/// Why a device with no relay mints no invite, in the device's own words: the
/// verb that sets its relay. A vault says the same thing about its settings
/// file (`kvaultd`'s `NO_RELAY`); the ceremony in `pairing.rs` cannot know
/// which it is, and an IPC door that answers a handler's error by closing says
/// nothing, so it is handed the relay and refuses none of its own.
const NO_RELAY_FOR_AN_INVITE: &str = "an invite meets at a relay and this device has none — \
     `kotton config relay set <url>` first";

/// Spawn and supervise the `ksyncd` sidecar process.
///
/// If `ksyncd` exits unexpectedly it is restarted with exponential backoff
/// (1 s â†' 2 s â†' â€¦ â†' 60 s).  A clean exit (status 0) is interpreted as an
/// intentional shutdown (e.g. when `kuserd` signals shutdown) and supervision
/// stops.
async fn supervise_ksyncd(
    token: Arc<sidecar_token::SidecarToken>,
    endpoint: IpcEndpoint,
    sidecar_states: Arc<RwLock<HashMap<String, SidecarState>>>,
) {
    // Locate the `ksyncd` binary next to the current process.
    let ksyncd_bin = sidecar_bin("ksyncd");

    // A socket is passed as a socket and a name as a name: the sidecar resolves
    // `KUSERD_IPC_SOCKET` as a path and `KUSERD_IPC_NAME` through the guard that
    // refuses one (`kotton_common::kuserd_socket_from_env`).
    let (ipc_var, ipc_value): (&str, String) = match &endpoint {
        #[cfg(windows)]
        IpcEndpoint::NamedPipe(name) => ("KUSERD_IPC_NAME", name.clone()),
        #[cfg(unix)]
        IpcEndpoint::UnixSocket(path) => ("KUSERD_IPC_SOCKET", path.to_string_lossy().into_owned()),
    };

    let mut backoff = std::time::Duration::from_secs(1);
    let mut restart_count: u32 = 0;
    let mut liveness = liveness::Liveness::default();
    loop {
        {
            use std::time::{SystemTime, UNIX_EPOCH};
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;
            let mut guard = sidecar_states.write().unwrap();
            let entry = guard.entry("ksyncd".to_string()).or_insert(SidecarState {
                enabled: true,
                running: false,
                pid: None,
                port: None,
                restart_count: 0,
                started_at: None,
                failed: None,
            });
            entry.running = true;
            entry.pid = None;
            entry.restart_count = restart_count;
            entry.started_at = Some(now);
        }

        // A token per start: the one before is bound to a pid that is gone.
        let bootstrap_token = token.mint();
        let started = std::time::Instant::now();
        let result = tokio::process::Command::new(&ksyncd_bin)
            .env("KSYNCD_BOOTSTRAP_TOKEN", &bootstrap_token)
            .env(ipc_var, &ipc_value)
            .spawn();
        // The child's pid, for the readout: `kotton sidecars` showed a dash here
        // while the process it described was running.
        let result = match result {
            Ok(mut child) => {
                if let Some(state) = sidecar_states.write().unwrap().get_mut("ksyncd") {
                    state.pid = child.id();
                }
                child.wait().await
            }
            Err(e) => Err(e),
        };

        {
            let mut guard = sidecar_states.write().unwrap();
            if let Some(state) = guard.get_mut("ksyncd") {
                state.running = false;
                state.pid = None;
            }
        }

        match &result {
            Ok(status) if status.success() => {
                tracing::info!("ksyncd exited cleanly; stopping supervision");
                return;
            }
            Ok(status) => {
                restart_count += 1;
                tracing::warn!(
                    code = ?status.code(),
                    "ksyncd exited unexpectedly; restarting in {backoff:?}"
                );
            }
            Err(e) => {
                restart_count += 1;
                tracing::warn!(
                    error = %e,
                    "ksyncd failed to spawn; retrying in {backoff:?}"
                );
            }
        }

        if let Some(reason) = liveness.exited(started.elapsed(), &result) {
            give_up("ksyncd", &sidecar_states, reason);
            return;
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(std::time::Duration::from_secs(60));
    }
}

/// Supervise the `kquicd` QUIC gateway sidecar.
///
/// If `kquicd` exits unexpectedly it is restarted with exponential backoff
/// (1 s → 2 s → … → 60 s).  A clean exit (status 0) is interpreted as an
/// intentional shutdown and supervision stops.
async fn supervise_kquicd(
    token: Arc<sidecar_token::SidecarToken>,
    endpoint: IpcEndpoint,
    sidecar_states: Arc<RwLock<HashMap<String, SidecarState>>>,
) {
    let kquicd_bin = sidecar_bin("kquicd");

    // A socket is passed as a socket and a name as a name: the sidecar resolves
    // `KUSERD_IPC_SOCKET` as a path and `KUSERD_IPC_NAME` through the guard that
    // refuses one (`kotton_common::kuserd_socket_from_env`).
    let (ipc_var, ipc_value): (&str, String) = match &endpoint {
        #[cfg(windows)]
        IpcEndpoint::NamedPipe(name) => ("KUSERD_IPC_NAME", name.clone()),
        #[cfg(unix)]
        IpcEndpoint::UnixSocket(path) => ("KUSERD_IPC_SOCKET", path.to_string_lossy().into_owned()),
    };

    let mut backoff = std::time::Duration::from_secs(1);
    let mut restart_count: u32 = 0;
    let mut liveness = liveness::Liveness::default();
    loop {
        {
            use std::time::{SystemTime, UNIX_EPOCH};
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;
            let mut guard = sidecar_states.write().unwrap();
            let entry = guard.entry("kquicd".to_string()).or_insert(SidecarState {
                enabled: true,
                running: false,
                pid: None,
                port: None,
                restart_count: 0,
                started_at: None,
                failed: None,
            });
            entry.running = true;
            entry.pid = None;
            entry.restart_count = restart_count;
            entry.started_at = Some(now);
        }

        // A token per start: the one before is bound to a pid that is gone.
        let bootstrap_token = token.mint();
        let started = std::time::Instant::now();
        let result = tokio::process::Command::new(&kquicd_bin)
            .env("KQUICD_BOOTSTRAP_TOKEN", &bootstrap_token)
            .env(ipc_var, &ipc_value)
            .spawn();
        // The child's pid, for the readout: `kotton sidecars` showed a dash here
        // while the process it described was running.
        let result = match result {
            Ok(mut child) => {
                if let Some(state) = sidecar_states.write().unwrap().get_mut("kquicd") {
                    state.pid = child.id();
                }
                child.wait().await
            }
            Err(e) => Err(e),
        };

        {
            let mut guard = sidecar_states.write().unwrap();
            if let Some(state) = guard.get_mut("kquicd") {
                state.running = false;
                state.pid = None;
            }
        }

        match &result {
            Ok(status) if status.success() => {
                tracing::info!("kquicd exited cleanly; stopping supervision");
                return;
            }
            Ok(status) => {
                restart_count += 1;
                tracing::warn!(
                    code = ?status.code(),
                    "kquicd exited unexpectedly; restarting in {backoff:?}"
                );
            }
            Err(e) => {
                restart_count += 1;
                tracing::warn!(
                    error = %e,
                    "kquicd failed to spawn; retrying in {backoff:?}"
                );
            }
        }

        if let Some(reason) = liveness.exited(started.elapsed(), &result) {
            give_up("kquicd", &sidecar_states, reason);
            return;
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(std::time::Duration::from_secs(60));
    }
}

/// Supervise the `khttpd` HTTP/WebSocket gateway sidecar.
///
/// Mirrors `supervise_kquicd`. Loops until `khttpd` exits with status 0 --
/// an intentional shutdown -- then stops supervision.
///
/// The gateway's configuration is read here and handed over at spawn
/// ([`kotton_device::config::ops::WebShell::spawn_env`]), and re-read on every
/// restart so a `WebShellSet` takes effect the next time the sidecar comes up.
/// `khttpd` holds a `Remote`-origin token and can reach no `Local`-tier verb, so
/// this is the only way its port and bind scope can reach it — by design, not
/// by exception: a gateway sidecar cannot reach its own bootstrap.
/// Start supervising the web-shell gateway if it is switched on and not
/// already running. Called at boot and by `WebShellSet`, so switching the
/// gateway on takes effect now rather than at the next restart — the setting
/// used to be read once at boot, and a person who flipped it saw nothing until
/// they rebooted, which the first container run of the harness found.
///
/// Switching it *off* live is not yet honoured: the supervision loop keeps the
/// process it holds until restart. Named here rather than hidden.
pub(super) async fn ensure_khttpd(ctx: &AgentContext) {
    let enabled = kotton_device::config::db::get_key(ctx.device_db.as_ref(), "web-shell.enabled")
        .await
        .ok()
        .flatten()
        .map(|v| v == "true")
        .unwrap_or(false);
    if !enabled {
        return;
    }
    if ctx
        .sidecar_states
        .read()
        .unwrap()
        .get("khttpd")
        .is_some_and(|s| s.running)
    {
        return;
    }
    // The daemon's own user, not an arbitrary user_id out of the
    // machine-wide paired_nodes.
    let Some(user_id) = ctx.users.any() else {
        tracing::info!("web shell is on but no user is resident yet; the gateway waits for one");
        return;
    };
    let token = sidecar_token::SidecarToken::new(
        Arc::clone(&ctx.sessions),
        Some(Arc::clone(&ctx.gateway_tokens)),
        user_id,
    );
    // khttpd is a gateway → its sessions are Remote.
    tokio::spawn(supervise_khttpd(
        token,
        ctx.endpoint.clone(),
        Arc::clone(&ctx.sidecar_states),
        Arc::clone(&ctx.device_db),
    ));
}

async fn supervise_khttpd(
    token: Arc<sidecar_token::SidecarToken>,
    endpoint: IpcEndpoint,
    sidecar_states: Arc<RwLock<HashMap<String, SidecarState>>>,
    device_db: Arc<SqlitePool>,
) {
    let khttpd_bin = sidecar_bin("khttpd");

    // A socket is passed as a socket and a name as a name: the sidecar resolves
    // `KUSERD_IPC_SOCKET` as a path and `KUSERD_IPC_NAME` through the guard that
    // refuses one (`kotton_common::kuserd_socket_from_env`).
    let (ipc_var, ipc_value): (&str, String) = match &endpoint {
        #[cfg(windows)]
        IpcEndpoint::NamedPipe(name) => ("KUSERD_IPC_NAME", name.clone()),
        #[cfg(unix)]
        IpcEndpoint::UnixSocket(path) => ("KUSERD_IPC_SOCKET", path.to_string_lossy().into_owned()),
    };

    let mut backoff = std::time::Duration::from_secs(1);
    let mut restart_count: u32 = 0;
    let mut liveness = liveness::Liveness::default();
    loop {
        {
            use std::time::{SystemTime, UNIX_EPOCH};
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;
            let mut guard = sidecar_states.write().unwrap();
            let entry = guard.entry("khttpd".to_string()).or_insert(SidecarState {
                enabled: true,
                running: false,
                pid: None,
                port: None,
                restart_count: 0,
                started_at: None,
                failed: None,
            });
            entry.running = true;
            entry.pid = None;
            entry.restart_count = restart_count;
            entry.started_at = Some(now);
        }

        let web_shell = match kotton_device::config::ops::web_shell(device_db.as_ref()).await {
            Ok(w) => w,
            Err(e) => {
                // Spawning without a configuration would put the daemon back on
                // guessed defaults, which is the defect this hand-over removed.
                restart_count += 1;
                tracing::warn!(error = %e, "could not read web-shell config; retrying in {backoff:?}");
                {
                    let mut guard = sidecar_states.write().unwrap();
                    if let Some(state) = guard.get_mut("khttpd") {
                        state.running = false;
                    }
                }
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(std::time::Duration::from_secs(60));
                continue;
            }
        };
        if let Some(state) = sidecar_states.write().unwrap().get_mut("khttpd") {
            state.port = Some(web_shell.port);
        }

        // A token per start: the one before is bound to a pid that is gone.
        let bootstrap_token = token.mint();
        let started = std::time::Instant::now();
        let result = tokio::process::Command::new(&khttpd_bin)
            .env("KHTTPD_BOOTSTRAP_TOKEN", &bootstrap_token)
            .env(ipc_var, &ipc_value)
            .envs(web_shell.spawn_env())
            .spawn();
        // The child's pid, for the readout: `kotton sidecars` showed a dash here
        // while the process it described was running.
        let result = match result {
            Ok(mut child) => {
                if let Some(state) = sidecar_states.write().unwrap().get_mut("khttpd") {
                    state.pid = child.id();
                }
                child.wait().await
            }
            Err(e) => Err(e),
        };

        {
            let mut guard = sidecar_states.write().unwrap();
            if let Some(state) = guard.get_mut("khttpd") {
                state.running = false;
                state.pid = None;
            }
        }

        match &result {
            Ok(status) if status.success() => {
                tracing::info!("khttpd exited cleanly; stopping supervision");
                return;
            }
            Ok(status) => {
                restart_count += 1;
                tracing::warn!(
                    code = ?status.code(),
                    "khttpd exited unexpectedly; restarting in {backoff:?}"
                );
            }
            Err(e) => {
                restart_count += 1;
                tracing::warn!(
                    error = %e,
                    "khttpd failed to spawn; retrying in {backoff:?}"
                );
            }
        }

        if let Some(reason) = liveness.exited(started.elapsed(), &result) {
            give_up("khttpd", &sidecar_states, reason);
            return;
        }
        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(std::time::Duration::from_secs(60));
    }
}

// -- kuid supervision ---------------------------------------------------------

/// Start kuid supervision if it is not already running.
///
/// Called on `AppInstall` and `AppLaunch` so an app sideloaded after the daemon
/// booted still gets a display server. Safe to call repeatedly — the guard on
/// `sidecar_states` prevents duplicate supervisor tasks.
///
/// This used to mint a bootstrap token against `users.any()` and return early
/// when there was no user, which made "can the machine show a window?" depend on
/// "has anybody logged in?". kuid is authorised by the descriptor it is handed
/// now, so there is nothing to mint and nobody to mint it for.
async fn ensure_kuid_running(
    sidecar_states: &Arc<RwLock<HashMap<String, SidecarState>>>,
    surface_proxy: &Arc<SurfaceProxy>,
    quitting: &tokio::sync::watch::Receiver<bool>,
) {
    if sidecar_states
        .read()
        .unwrap()
        .get("kuid")
        .map(|s| s.running)
        .unwrap_or(false)
    {
        return;
    }
    tracing::info!("kuid was not running — starting supervision");
    tokio::spawn(supervise_kuid(
        Arc::clone(sidecar_states),
        Arc::clone(surface_proxy),
        quitting.clone(),
    ));
}

/// Unlike `kquicd`/`khttpd`, `kuid` is spawned whenever there are any
/// registered apps — display is always needed.  Exponential backoff
/// (1 s → 2 s → … → 60 s) on crash; clean exit (status 0) stops supervision.
///
/// Not `#[cfg]`-split. The channel underneath it is a pair of pipes, and pipes
/// exist identically on both platforms, so there is one function — and no
/// guarantee is true on one platform and asserted on both, by construction
/// rather than by a guard.
/// **Did the window close and leave a daemon behind?**
///
/// Quitting Kotton stops the daemon; closing the window does not. The two
/// gestures are indistinguishable at the exit status — closing the window is an ordinary, successful leave, and *Quit Kotton*
/// is too — so the daemon's own state is what separates them, and it is read
/// here rather than in the middle of a supervision loop nothing can call.
///
/// A crash is neither: `supervise_kuid` restarts it, so no window has finally
/// closed and there is nothing to tell the person.
fn kuid_left_the_window_up(exited_cleanly: bool, the_person_quit: bool) -> bool {
    exited_cleanly && !the_person_quit
}

async fn supervise_kuid(
    sidecar_states: Arc<RwLock<HashMap<String, SidecarState>>>,
    surface_proxy: Arc<SurfaceProxy>,
    // Whether the daemon is stopping because the person quit. Read, never
    // awaited: a clean `kuid` exit means two different things depending on
    // which gesture produced it, and this is the only thing that tells them
    // apart — see `kuid_left_the_window_up`.
    quitting: tokio::sync::watch::Receiver<bool>,
) {
    let kuid_bin = sidecar_bin("kuid");

    // kuid is told nothing about how to reach kuserd, because it has no reason
    // to reach it: the pair handed in below is the whole conversation, both
    // directions.
    //
    // There used to be a `KUSERD_ENDPOINT` here, and a long note about how it
    // came to be passed verbatim — kuid had derived the path itself and derived
    // it wrongly, joining an absolute path onto a directory and crash-looping on
    // a plausible-looking path nothing binds. The note ended by saying the end
    // state is no path at all. This is that state; the note is kept in the git
    // history rather than describing a variable that no longer exists.

    let mut backoff = std::time::Duration::from_secs(1);
    let mut restart_count: u32 = 0;
    loop {
        {
            use std::time::{SystemTime, UNIX_EPOCH};
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;
            let mut guard = sidecar_states.write().unwrap();
            let entry = guard.entry("kuid".to_string()).or_insert(SidecarState {
                enabled: true,
                running: false,
                pid: None,
                port: None,
                restart_count: 0,
                started_at: None,
                failed: None,
            });
            entry.running = true;
            entry.pid = None;
            entry.restart_count = restart_count;
            entry.started_at = Some(now);
        }

        // The surface channel is a pair of pipes made here, by the spawn. kuid
        // binds nothing and there is no path, so the only process that can speak
        // on it is the one holding the other end — us. That is why kuid has no
        // admission check: there is no question to ask, and no socket to
        // connect to.
        //
        // Two anonymous pipes, created by the spawn itself. `Stdio::piped()` is
        // the same mechanism the guest runner uses, and it is the reason there
        // is nothing to name: a pipe has no filesystem presence at all, so the
        // question of who may open it does not arise.
        //
        // Not a `socketpair`, which would be a Windows build error --
        // `std::os::unix::net::UnixStream::pair` and `tokio::net::unix` do not
        // exist there. A socket would buy nothing over a pair of pipes: the child reads stdin and writes stdout either way,
        // and this version needs no `try_clone`, no `OwnedFd` conversion, and no
        // reasoning about whether a child can rebuild a socket from a bare
        // descriptor. Every security property is unchanged, because they all
        // came from *handing the child its ends at spawn*, not from the socket.

        let result = tokio::process::Command::new(&kuid_bin)
            // Nothing is *added* to the environment here. A bootstrap token and an
            // endpoint used to go in, and between them they were kuid's entire
            // ability to act as a client of this daemon. Deleting the two variables
            // is what deleting that reach looks like at the spawn site.
            //
            // It is not `env_clear()`, and the difference is load-bearing: kuid
            // inherits this process's environment, which is how it sees the display
            // variables and `WSL_DISTRO_NAME` that decide which display server it
            // talks to and whether it draws its own window frame
            // (`wants_client_decorations`, `core/kuid/src/main.rs`). Anything added
            // here reaches the compositor, so add nothing without asking what it
            // lets the compositor do.
            //
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn();

        let mut child = match result {
            Ok(c) => c,
            Err(e) => {
                tracing::error!(error = %e, "kuid: could not spawn");
                return;
            }
        };

        // Attach before awaiting the child, so a surface event racing its
        // startup finds a channel rather than a missing one.
        match (child.stdin.take(), child.stdout.take()) {
            (Some(w), Some(r)) => surface_proxy.attach(w, r).await,
            _ => {
                tracing::error!("kuid: spawn returned no pipes");
                return;
            }
        }

        let result = child.wait().await;

        // The child is gone, so the pair is broken. Drop our end so a caller
        // gets a clear failure rather than writing into a dead socket.
        surface_proxy.detach().await;

        {
            let mut guard = sidecar_states.write().unwrap();
            if let Some(state) = guard.get_mut("kuid") {
                state.running = false;
                state.pid = None;
            }
        }

        match result {
            Ok(status) if status.success() => {
                tracing::info!("kuid exited cleanly; stopping supervision");
                // **Which gesture was it?** Both leave through the same clean
                // exit, and only one of them leaves a daemon behind. The
                // sentence below is the recipe's, read out of this log
                // (`kotton_common::KUID_LEFT_LINE`), so saying it on the quit
                // path would tell the person the daemon is still running an
                // instant before it stops.
                if kuid_left_the_window_up(status.success(), *quitting.borrow()) {
                    tracing::info!("{}", kotton_common::KUID_LEFT_LINE);
                }
                return;
            }
            Ok(status) => {
                restart_count += 1;
                tracing::warn!(
                    code = ?status.code(),
                    "kuid exited unexpectedly; restarting in {backoff:?}"
                );
            }
            Err(e) => {
                restart_count += 1;
                tracing::warn!(
                    error = %e,
                    "kuid failed to spawn; retrying in {backoff:?}"
                );
            }
        }

        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(std::time::Duration::from_secs(60));
    }
}

// -- kinferd supervision ------------------------------------------------------

/// Spawn and supervise the `kinferd` inference runtime.
///
/// The same shape as [`supervise_kuid`] and for the same reason: the channel is
/// a pair of pipes made *by this spawn*, so there is no path, nothing for a
/// third process to open, and no admission check to write. A model server on a
/// loopback port is refused as the design — a port on the loopback interface is
/// reachable by every process of that user — and that refusal is only worth
/// anything if the daemon's own runtime does not quietly take it.
///
/// **The environment is cleared** — `.env_clear()` on the spawn below, not just
/// an absence of `.env()` calls. `kinferd` is told nothing about how to reach
/// `kuserd`, because the pair handed in below is the whole conversation, both
/// directions. Nothing about a session, a user or a key goes in, and nothing
/// `kuserd` itself was started with is passed along.
///
/// One cost, stated because it is invisible otherwise: `kinferd` reads
/// `RUST_LOG` through `EnvFilter::try_from_default_env`, so with the environment
/// cleared that lookup always fails and the sidecar logs at its own default
/// (`kinferd=info,warn`). Raising its verbosity means changing that default, not
/// exporting a variable. Forwarding the one variable was the alternative and was
/// not taken: "no environment" that a reader can check against a single line is
/// worth more than a log filter, and this is the one process in the tree that
/// parses a file an attacker may have written.
///
/// Exponential backoff (1 s → 2 s → … → 60 s) on crash; a clean exit (status 0)
/// stops supervision. A weights file is untrusted input, so a crash here is the
/// expected failure mode rather than a surprise — and it is a crash of a keyless
/// process, which is what the separation bought.
///
/// **And an unclean exit is written down.** The child's stderr is piped and
/// drained, and the last line it said goes into `SidecarState.failed` beside its
/// exit code — because the failure this supervisor most needs to survive is a
/// refused frame, which `kinferd` reports on stderr and nowhere else.
/// Containment that ends in silence is half a design: the person is told how
/// long and how many, and that needs the daemon to know the runtime stopped and
/// why.
///
/// # Why the binary is a parameter, and why this is public
///
/// The other `supervise_*` functions call `sidecar_bin` themselves, which
/// resolves a name beside the *current* executable. That is right for a daemon
/// and unusable from a test, whose current executable is a hashed binary under
/// `target/debug/deps`. Resolving once at the call site and handing the path
/// down is the move `runner_from_environment` already made for the sandbox —
/// *which process is this* becomes a thing the caller holds rather than an
/// ambient fact re-derived at every spawn.
///
/// Public so a test can prove the pipe by running **this** function, not a copy
/// of it: a supervisor exercised only by a re-implementation of itself proves the
/// re-implementation. No case in this repository's suite does, since it builds no
/// `kinferd` (kottonllc/kotton#24, #16).
pub async fn supervise_kinferd(
    kinferd_bin: PathBuf,
    sidecar_states: Arc<RwLock<HashMap<String, SidecarState>>>,
    infer_proxy: Arc<InferProxy>,
) {
    let mut backoff = std::time::Duration::from_secs(1);
    let mut restart_count: u32 = 0;
    loop {
        {
            use std::time::{SystemTime, UNIX_EPOCH};
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;
            let mut guard = sidecar_states.write().unwrap();
            let entry = guard.entry("kinferd".to_string()).or_insert(SidecarState {
                enabled: true,
                running: false,
                pid: None,
                port: None,
                restart_count: 0,
                started_at: None,
                failed: None,
            });
            entry.running = true;
            entry.pid = None;
            entry.restart_count = restart_count;
            entry.started_at = Some(now);
        }

        let mut command = tokio::process::Command::new(&kinferd_bin);
        command
            // Cleared, not merely unset: without this the child inherits every
            // variable `kuserd` holds, and "no environment" above would be a
            // claim the code did not keep. Nothing in the
            // process tree is a capability by itself, but an operator's exported
            // secret is not this process's business, and a promise a reader can
            // check against one line is worth more than one they cannot.
            .env_clear()
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            // Piped rather than inherited, because this is where the child says
            // *why* it stopped. Every line is re-emitted through the daemon's
            // own logging below, so nothing a person could read before is lost;
            // what is gained is that the last one is still in hand when the exit
            // status arrives.
            .stderr(std::process::Stdio::piped());

        // The operating system's half of the weights parser's confinement
        // (`docs/design/processes.md`). Everything above is
        // what this process is *given*; this is what it may reach, and the
        // answer is its own program and nothing else. The weights arrive as
        // `Load` frames down the pipe already attached, so `kinferd` needs no
        // path at all — which is why its profile is two lines and why that was
        // worth checking before a backend was chosen rather than after.
        if let Err(e) = kotton_proc::confine(
            &mut command,
            &kotton_proc::Profile::nothing("kinferd").executing(&kinferd_bin),
        ) {
            // Not a warning and not a fallback. An engine that cannot be
            // confined does not run, and that is the whole of why the
            // `Unsupported` variant exists.
            give_up("kinferd", &sidecar_states, format!("is not confined: {e}"));
            return;
        }

        let result = command.spawn();

        let mut child = match result {
            Ok(c) => c,
            Err(e) => {
                give_up("kinferd", &sidecar_states, format!("could not spawn: {e}"));
                return;
            }
        };

        if let Some(state) = sidecar_states.write().unwrap().get_mut("kinferd") {
            state.pid = child.id();
        }

        // Attach before awaiting the child, so a question racing its startup
        // finds a channel rather than a missing one.
        match (child.stdin.take(), child.stdout.take()) {
            (Some(w), Some(r)) => infer_proxy.attach(w, r).await,
            _ => {
                give_up(
                    "kinferd",
                    &sidecar_states,
                    "spawn returned no pipes".to_string(),
                );
                return;
            }
        }

        // Drain stderr as it is written, not after the child exits. A pipe
        // nobody reads fills, and a child that blocks writing to it never
        // reaches the exit whose status this loop is waiting for — the deadlock
        // is silent and looks like a hung sidecar.
        let last_line = Arc::new(std::sync::Mutex::new(String::new()));
        let drain = child.stderr.take().map(|stderr| {
            let last_line = Arc::clone(&last_line);
            tokio::spawn(async move {
                use tokio::io::AsyncBufReadExt;
                let mut lines = tokio::io::BufReader::new(stderr).lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    // Re-emitted so piping it costs a reader nothing, and
                    // through `tracing` rather than to raw stderr so it is
                    // escaped and attributed to the child that said it.
                    tracing::info!(sidecar = "kinferd", "{line}");
                    let kept: String = line.chars().take(STDERR_REASON_MAX).collect();
                    *last_line.lock().unwrap() = kept;
                }
            })
        });

        let result = child.wait().await;

        // The child is gone, so its stderr is at EOF and the drain is about to
        // finish. Bounded anyway: a supervisor that can be made to wait forever
        // by a child that will not close a descriptor is a supervisor a child
        // can switch off.
        if let Some(drain) = drain {
            let _ = tokio::time::timeout(std::time::Duration::from_secs(5), drain).await;
        }
        let last_line = last_line.lock().unwrap().clone();

        // What **this end** refused, if it refused anything. Taken before the
        // next spawn, because it explains the exit that just happened and
        // nothing after it.
        //
        // This is the half the exit code cannot carry. Refusing a frame from the
        // runtime drops the daemon's end of the pair, which closes the child's
        // stdin, so the child reads end-of-stream and exits **0** — and 0 is how
        // a sidecar says it was asked to stop. Read on its own, that status sent
        // supervision home with nothing recorded, which is exactly the scenario
        // the weights parser is put in its own process to survive: a
        // parser made to emit one bad byte would end inference for the daemon's
        // lifetime, unreported.
        let refused = infer_proxy.take_refusal();

        // The child is gone, so the pair is broken. Drop our end so a caller
        // gets a clear failure rather than writing into a dead pipe.
        infer_proxy.detach().await;

        {
            let mut guard = sidecar_states.write().unwrap();
            if let Some(state) = guard.get_mut("kinferd") {
                state.running = false;
                state.pid = None;
            }
        }

        match result {
            // A clean exit stops supervision — but only when nothing on this end
            // caused it. `refused.is_none()` is the whole of that condition, and
            // it is load-bearing: a refusal here produces a status of 0, and
            // reading the status alone cannot tell *it was asked to stop* from
            // *it said something this end would not accept*.
            Ok(status) if status.success() && refused.is_none() => {
                tracing::info!("kinferd exited cleanly; stopping supervision");
                return;
            }
            // Everything else is a failure to **report**. Either the runtime
            // refused what the daemon sent — undecodable, or over the frame
            // ceiling — and said so on stderr before exiting non-zero, or the
            // daemon refused what the runtime sent and closed the pair. The person
            // is told how long and how many, which needs the daemon
            // to know the runtime stopped and why.
            Ok(status) => {
                restart_count += 1;
                let code = status
                    .code()
                    .map(|c| c.to_string())
                    .unwrap_or_else(|| "a signal".to_string());
                // A refusal on this end explains the exit better than the status
                // does, so it is preferred to both the status and the child's
                // own last words.
                let reason = match (&refused, last_line.is_empty()) {
                    (Some(refusal), _) => format!(
                        "exited with status {code} because this end refused what it sent: {refusal}"
                    ),
                    (None, true) => {
                        format!("exited with status {code} and said nothing on stderr")
                    }
                    (None, false) => format!("exited with status {code}: {last_line}"),
                };
                note_failure("kinferd", &sidecar_states, reason);
                tracing::warn!("kinferd restarting in {backoff:?}");
            }
            Err(e) => {
                restart_count += 1;
                note_failure(
                    "kinferd",
                    &sidecar_states,
                    format!("could not be waited on: {e}"),
                );
                tracing::warn!("kinferd retrying in {backoff:?}");
            }
        }

        tokio::time::sleep(backoff).await;
        backoff = (backoff * 2).min(std::time::Duration::from_secs(60));
    }
}

/// The capabilities a bundled app's manifest declares.
///
/// Bundled apps ship inside this binary, so "what the manifest asks for" and
/// "what the system approved" are the same statement — the review happened when
/// the app was compiled in. Written as a function rather than inlined so the
/// step is visible: `ApprovedCapabilities` has no `From<AppManifest>` precisely
/// so that this conversion has to be spelled somewhere a reader can find it.
///
/// An unparseable bundled manifest approves nothing; `app_install` will fail on
/// the same manifest a moment later and report why.
fn bundled_manifest_capabilities(manifest_toml: &str) -> Vec<kotton_schemas::CapabilityGrant> {
    kotton_schemas::AppManifest::from_toml(manifest_toml)
        .map(|m| m.capabilities.iter().cloned().collect())
        .unwrap_or_default()
}

#[cfg(test)]
mod unlock_tests;

#[cfg(test)]
mod set_lock_policy_tests;

#[cfg(test)]
mod message_open_tests;

#[cfg(test)]
mod revoke_device_tests;

#[cfg(test)]
mod peer_key_tests;

#[cfg(test)]
mod co_member_tests;

/// **The two gestures, told apart by the one fact that distinguishes them.**
///
/// Quitting Kotton stops the daemon; closing the window does not. kuid
/// decides which gesture it saw (`core/kuid/src/main.rs`, `what_leaving_means`)
/// and reports *Quit* up the surface channel; this is the daemon's half —
/// having heard it or not, what does a clean `kuid` exit now mean?
#[cfg(test)]
mod leaving {
    use super::kuid_left_the_window_up;

    /// The X: kuid leaves cleanly, nobody quit, and the daemon is still there
    /// to be told about.
    #[test]
    fn the_x_leaves_a_daemon_to_tell_the_person_about() {
        assert!(kuid_left_the_window_up(true, false));
    }

    /// *Quit Kotton*: the same clean exit, and the sentence would be a lie.
    ///
    /// This is the assertion with teeth. The exit status is identical on both
    /// paths by design — both are ordinary, complete leaves — so a supervisor reading the status alone cannot help but say
    /// *the daemon is still running* while `serve` is returning.
    #[test]
    fn quitting_says_nothing_about_a_daemon_that_is_stopping() {
        assert!(!kuid_left_the_window_up(true, true));
    }

    /// A crash is neither gesture: supervision restarts it, so no window has
    /// finally closed.
    #[test]
    fn a_crash_is_not_a_window_closing() {
        assert!(!kuid_left_the_window_up(false, false));
        assert!(!kuid_left_the_window_up(false, true));
    }
}

#[cfg(test)]
mod runner_resolution {
    use super::resolve_runner;
    use std::path::{Path, PathBuf};

    fn runner_in(dir: &Path) -> PathBuf {
        let bin = dir.join(format!("kotton-runner{}", std::env::consts::EXE_SUFFIX));
        std::fs::write(&bin, b"").expect("write a stand-in runner");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755))
                .expect("make it executable");
        }
        bin
    }

    /// The case that broke: no `KOTTON_RUNNER`, the runner installed on
    /// `PATH`. The sandbox grants the runner by opening it, and an open of a
    /// bare name looks in the working directory — so the daemon has to hand it
    /// the path the spawn's own `PATH` search used to find.
    #[test]
    fn a_runner_named_by_path_alone_resolves_to_where_it_is() {
        let empty = tempfile::tempdir().expect("tempdir");
        let installed = tempfile::tempdir().expect("tempdir");
        let bin = runner_in(installed.path());
        let path = std::env::join_paths([empty.path(), installed.path()]).expect("join");
        let cwd = tempfile::tempdir().expect("tempdir");

        let got = resolve_runner(None, None, Some(path), Some(cwd.path().to_path_buf()));
        assert_eq!(got, bin);
        assert!(got.is_absolute());
    }

    /// A file of the right name that cannot be executed is not what `execvp`
    /// would have run, so it is not what the daemon picks either.
    #[cfg(unix)]
    #[test]
    fn a_runner_without_an_execute_bit_is_passed_over() {
        let shadow = tempfile::tempdir().expect("tempdir");
        std::fs::write(shadow.path().join("kotton-runner"), b"").expect("write");
        let installed = tempfile::tempdir().expect("tempdir");
        let bin = runner_in(installed.path());
        let path = std::env::join_paths([shadow.path(), installed.path()]).expect("join");

        assert_eq!(resolve_runner(None, None, Some(path), None), bin);
    }

    /// A relative `KOTTON_RUNNER` is anchored where the daemon started, so a
    /// grant opened later reads the same file the variable meant.
    #[test]
    fn a_relative_kotton_runner_is_anchored_to_the_working_directory() {
        let cwd = PathBuf::from("/srv/kotton");
        let got = resolve_runner(
            Some("target/debug/kotton-runner".into()),
            None,
            None,
            Some(cwd.clone()),
        );
        assert_eq!(got, cwd.join("target/debug/kotton-runner"));
    }

    /// An installed Kotton: the runner beside the daemon is the one it runs,
    /// even with another `kotton-runner` earlier on `PATH` — the sandbox is the
    /// one that shipped with this daemon, not the one a `PATH` happened to name.
    #[test]
    fn the_runner_beside_the_daemon_wins_over_path() {
        let bin_dir = tempfile::tempdir().expect("tempdir");
        let shipped = runner_in(bin_dir.path());
        let elsewhere = tempfile::tempdir().expect("tempdir");
        runner_in(elsewhere.path());
        let path = std::env::join_paths([elsewhere.path()]).expect("join");

        let got = resolve_runner(None, Some(bin_dir.path().to_path_buf()), Some(path), None);
        assert_eq!(got, shipped);
    }

    /// Nothing beside the daemon — a daemon installed on its own — and `PATH`
    /// still finds one, as it did before.
    #[test]
    fn with_nothing_beside_the_daemon_path_still_resolves() {
        let bin_dir = tempfile::tempdir().expect("tempdir");
        let installed = tempfile::tempdir().expect("tempdir");
        let bin = runner_in(installed.path());
        let path = std::env::join_paths([installed.path()]).expect("join");

        let got = resolve_runner(None, Some(bin_dir.path().to_path_buf()), Some(path), None);
        assert_eq!(got, bin);
    }

    /// `KOTTON_RUNNER` still names the runner outright: a checkout that points
    /// it at its own build is not overridden by what sits beside the daemon.
    #[test]
    fn kotton_runner_still_wins_over_what_is_beside_the_daemon() {
        let bin_dir = tempfile::tempdir().expect("tempdir");
        runner_in(bin_dir.path());
        let named = PathBuf::from("/opt/elsewhere/kotton-runner");

        let got = resolve_runner(
            Some(named.clone().into()),
            Some(bin_dir.path().to_path_buf()),
            None,
            None,
        );
        assert_eq!(got, named);
    }
}
