// SPDX-License-Identifier: AGPL-3.0-or-later
//! Shared integration-test harness.
//!
//! Each test calls [`TestEnv::spawn`] which:
//! 1. Creates an isolated [`tempfile::TempDir`] so tests never share storage.
//! 2. Generates a unique named pipe / socket name so parallel test binaries
//!    don't collide.
//! 3. Boots a [`DeviceDaemon`] in a background Tokio task.
//! 4. Connects a [`KottonClient`] and returns `TestEnv`.
//!
//! When `TestEnv` is dropped the background task is aborted automatically.
//!
//! ## Why `dead_code` is allowed here
//!
//! This module is compiled **into every integration test binary separately**,
//! and each one uses a different slice of it. Rust judges "used" per compilation
//! unit, so every binary warns about the parts the *other* binaries need —
//! `spawn_authed` alone has 59 call sites and still warns.
//!
//! Verified 2026-08-19 rather than assumed: every field and function flagged
//! here is reached from some test. This is a false positive by construction, not
//! a suppression of real dead code — so treat additions to this file as needing
//! a caller, exactly as anywhere else, because the allow will hide it if they
//! do not have one.
#![allow(dead_code)]

pub mod bins;
pub mod s3;
pub mod relay;
pub mod cli;

/// Where a test daemon's socket goes.
///
/// Not a style choice — it decides whether a separate process can find the
/// daemon at all. See [`TestEnv::spawn_cli_reachable`].
#[derive(Clone, Copy, PartialEq, Eq)]
enum Placement {
    /// A unique path the test hands to `connect_to`. Every library-client test.
    Isolated,
    /// The path `kotton` computes for itself from `KOTTON_BASE_DIR`.
    CliDiscoverable,
}

use kotton_device::config::db::RelayChoice;
use kuserd::DeviceDaemon;
use kotton_sys::ipc::IpcEndpoint;
use kotton_sys::secret::SecretsStore;
use kotton_secret::MemorySecrets;
use kotton::{KottonClient, PairedNode, UserResponse};
use kotton_schemas::membership::Posture;
use tokio::sync::oneshot;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;
use tokio::task::JoinHandle;
use uuid::Uuid;

/// Create a vault at `base` for an operator key the suite mints, as `kvaultd
/// create` does before any vault serves (RFC-0084 V18), with `secrets` as the
/// provider its own key is kept in — the one the test then serves it with. A
/// vault does not start without an operator (V19), so every in-process vault in
/// the suite is created first. Returns the operator's key; a test's own
/// operators are enrolled beside it at the door.
pub async fn create_vault(base: &std::path::Path, secrets: &(dyn SecretsStore + Send + Sync)) -> ed25519_dalek::SigningKey {
    // The suite's own temporary directory, closed as an installer leaves a
    // state directory: `tempfile` makes it by the umask, `0755` under `022`,
    // and `create` and every start use an existing state directory only when
    // it is `0700` and the running user's — they chmod nothing they did not
    // make (`TASK-kvaultd-create-chmods-any-existing-directory-it-is-pointed-at`).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(base, std::fs::Permissions::from_mode(0o700)).expect("the suite's vault base is its own");
    }
    let operator = ed25519_dalek::SigningKey::from_bytes(&rand::random());
    kvaultd::instance::create(base, secrets, &hex::encode(operator.verifying_key().to_bytes()), String::new())
        .await
        .expect("the vault is created for the suite's operator");
    operator
}

/// Block until the daemon on `endpoint` is accepting IPC connections.
///
/// Tests that build their own multi-daemon topologies cannot use
/// [`TestEnv::spawn`] — they need specific ports, peer listeners, or three nodes —
/// and every one of them instead slept a fixed interval after `daemon.run()`.
///
/// **A sleep is a guess about scheduling, not a fact about the daemon.** Under the
/// full suite the machine is oversubscribed, so 200ms is sometimes enough and
/// sometimes not, which is the definition of a flaky test. `enroll_threshold_sign`
/// failed exactly this way on 2026-08-20 — the joiner's `device_join_stream` call
/// hit a listener that had not bound yet — and passed 9/9 in isolation minutes
/// later. It cost two full gate cycles before it was fixed rather than retried.
///
/// Polling is also *faster* in the common case: it returns the instant the listener
/// is up, where the sleep always paid its full 200ms.
/// Install the process-wide TLS crypto provider once. Every daemon a test
/// starts needs it, and the second installation is an error, so it is a `Once`.
pub fn init_crypto() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        rustls::crypto::ring::default_provider()
            .install_default()
            .ok();
    });
}

/// A fresh IPC endpoint no other test is listening on.
///
/// `$TMPDIR/kotton-test-<id>.sock`, or the same name in a fresh `0o700` directory
/// under `/tmp` when the first does not fit `sun_path` — [`door_in`], asked of
/// `TMPDIR`. The [`Door`] removes what it made when the caller drops it, which is
/// the end of the test for every caller that binds it with `let`.
///
/// Until 2026-09-28 the fallback was `/tmp/kotton-test-<id>.sock`, straight into
/// world-writable `/tmp`, and nothing removed either form: one package-scoped run
/// under a long `TMPDIR` left 75 of them behind
/// (`TASK-suite-tests-that-join-their-own-socket-path-cannot-bind-under-a-long-tmpdir`).
pub fn unique_ipc() -> Door {
    let id = uuid::Uuid::new_v4().simple().to_string();
    #[cfg(windows)]
    return Door::pipe(format!("kotton-test-{id}"));
    #[cfg(unix)]
    door_in(&std::env::temp_dir(), &format!("kotton-test-{id}.sock"))
}

/// A test daemon's socket, and the directory outside the base it was asked for
/// that holds it, if it had to go there.
///
/// Dropping it removes that directory, or the socket file when there is none: the
/// harness made both, so the harness removes both. It dereferences to its
/// [`IpcEndpoint`], so `door.clone()` and `&door` read where an endpoint did.
/// [`TestEnv`] holds its own and drops them after its daemon has shut down.
pub struct Door {
    endpoint: IpcEndpoint,
    dir_outside_base: Option<PathBuf>,
}

impl Door {
    /// The path the daemon binds.
    #[cfg(unix)]
    pub fn socket(&self) -> &std::path::Path {
        let IpcEndpoint::UnixSocket(path) = &self.endpoint;
        path
    }

    /// A named pipe, which has no file to remove.
    #[cfg(windows)]
    pub fn pipe(name: String) -> Self {
        Door { endpoint: IpcEndpoint::NamedPipe(name), dir_outside_base: None }
    }
}

impl std::ops::Deref for Door {
    type Target = IpcEndpoint;
    fn deref(&self) -> &IpcEndpoint {
        &self.endpoint
    }
}

impl Drop for Door {
    fn drop(&mut self) {
        if let Some(dir) = self.dir_outside_base.take() {
            let _ = std::fs::remove_dir_all(dir);
            return;
        }
        #[cfg(unix)]
        {
            let _ = std::fs::remove_file(self.socket());
        }
    }
}

/// The door for a socket named `file` that a test wants under `base`.
///
/// `<base>/<file>` when that fits `sun_path` by the product's own measure,
/// [`kotton_common::paths::socket_path_fits`]. Otherwise the same name in a fresh
/// `0o700` directory under `/tmp`, whose path length the harness sets rather than
/// whoever set `TMPDIR`. Not the product's fallback: a test's door is handed to
/// whoever dials it and never looked for, so nothing else has to derive it — only
/// the question of whether it fits is shared.
///
/// **Every socket a suite test binds comes from here**, through [`unique_ipc`],
/// [`TestEnv::door`] or [`isolated_door`]. Before 2026-09-28 five files kept a
/// private copy of `unique_ipc`'s old `$TMPDIR` join and three more joined a
/// `.sock` onto a tempdir by hand, and seven tests failed under a long `TMPDIR`
/// after a 60 s wait with "path must be shorter than SUN_LEN"
/// (`TASK-suite-tests-that-join-their-own-socket-path-cannot-bind-under-a-long-tmpdir`).
#[cfg(unix)]
pub fn door_in(base: &std::path::Path, file: &str) -> Door {
    let socket = base.join(file);
    if kotton_common::paths::socket_path_fits(&socket) {
        return Door { endpoint: IpcEndpoint::UnixSocket(socket), dir_outside_base: None };
    }
    // `0o700` asked for at `mkdir`, not after: `tempdir_in` alone takes the
    // default mode (`0o755` under the usual umask), which is what `isolated_door`
    // made until `a_door_is_private_when_it_leaves_its_base_and_goes_when_dropped`
    // measured it.
    use std::os::unix::fs::PermissionsExt as _;
    let dir = tempfile::Builder::new()
        .prefix("kotton-test-")
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir_in("/tmp")
        .expect("create a short directory under /tmp for a test daemon's socket")
        .keep();
    Door { endpoint: IpcEndpoint::UnixSocket(dir.join(file)), dir_outside_base: Some(dir) }
}

/// The door an [`Placement::Isolated`] daemon binds: `daemon-<unique>.sock`, by
/// [`door_in`]. Before 2026-09-28 the joined path was used as is, and under a long
/// `TMPDIR` every such test failed after a 30 s connection timeout with "path must
/// be shorter than SUN_LEN"
/// (`TASK-a-suite-daemon-placed-isolated-cannot-bind-under-a-long-tmpdir`).
#[cfg(unix)]
fn isolated_door(base: &std::path::Path, unique: &str) -> Door {
    door_in(base, &format!("daemon-{unique}.sock"))
}

/// The door a [`Placement::CliDiscoverable`] daemon binds: wherever
/// [`cli::discoverable_socket`] says, which under a long `TMPDIR` is the product's
/// `/tmp/kotton-<hash>/` fallback. The daemon creates that directory and nothing
/// removed it, so each such test left one behind; it is named here so the drop can,
/// by the rule's own [`kotton_common::paths::daemon_socket_fallback_dir`] rather than
/// by the socket's not being under `base`, which was this harness's copy of the rule
/// until 2026-09-28 (`TASK-the-deep-box-vault-test-leaves-its-short-door-in-tmp`).
#[cfg(unix)]
fn discoverable_door(base: &std::path::Path) -> Door {
    let socket = cli::discoverable_socket(base);
    let dir_outside_base = kotton_common::paths::daemon_socket_fallback_dir(&socket).map(std::path::Path::to_path_buf);
    Door { endpoint: IpcEndpoint::UnixSocket(socket), dir_outside_base }
}

pub async fn wait_for_daemon(endpoint: &IpcEndpoint, label: &str) {
    drop(connect_when_ready(endpoint, label).await);
}

/// Connect to `endpoint`, retrying until the daemon accepts.
///
/// **Use this instead of `KottonClient::connect_to` after a
/// [`wait_for_daemon`], because the readiness probe is not free.** It proves
/// the listener is up by *connecting*, and on Windows a named-pipe server holds
/// a finite set of instances: between the probe dropping its handle and the
/// server arming a fresh one there is a window where a new connect fails with
/// `ERROR_PIPE_BUSY` — "All pipe instances are busy. (os error 231)".
///
/// That is exactly how `schema_grants::grants_persist_across_restart` failed on
/// 2026-08-20, and it was **introduced by the fix that removed the sleeps**: a
/// sleep is a passive guess, but a probe is an action, and replacing one with
/// the other traded a timing assumption for a resource one. Retrying the
/// connect removes both — the deadline is the only assumption left, and it is
/// generous enough never to be reached on a healthy run.
pub async fn connect_when_ready(endpoint: &IpcEndpoint, label: &str) -> KottonClient {
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    loop {
        match KottonClient::connect_to(endpoint.clone()).await {
            Ok(client) => return client,
            // Reported where it is produced rather than stashed: the last error
            // is only ever wanted at the deadline, and holding it in a binding
            // the success path never reads is a warning waiting to happen.
            Err(e) if std::time::Instant::now() > deadline => {
                panic!("{label} did not accept an IPC connection within 60s (last error: {e})")
            }
            Err(_) => {}
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// A self-contained daemon + client pair for one test.
/// The unlock credential every test identity is created with.
///
/// Five words **all of which are on the BIP-39 list**, so `entropy_bits` scores
/// it by the wordlist path at exactly 5 x 11 = 55.00 bits, clearing the 50-bit
/// bar the way a real generated credential does.
///
/// That is not a detail. The first draft of this constant was
/// `canyon ember thistle plover quartz`, of which only `canyon` is on the list —
/// so it fell to the charset estimator, scored 200.01, and would have passed for
/// the same reason `passwordpassword1` passes
/// (`TASK-the-entropy-estimator-scores-a-dictionary-password-at-83-bits`). A
/// fixture that clears the bar through the broken path tests nothing about the
/// bar.
///
/// A constant rather than `generate()`, so a failing test fails the same way
/// twice.
pub const TEST_PASSPHRASE: &str = "canyon-orbit-velvet-fish-hospital";

pub struct TestEnv {
    /// Ready-to-use client connected to the test daemon.
    pub client: KottonClient,
    /// IPC endpoint the test daemon is listening on.
    /// Use this to open additional client connections in the same test.
    pub endpoint: IpcEndpoint,
    /// In-memory secrets store — inject into the daemon, manipulate in tests.
    pub secrets: Arc<dyn SecretsStore + Send + Sync>,
    /// Base directory for the daemon's storage.
    /// Use this to write raw fixture files into user storage.
    pub base_dir: std::path::PathBuf,
    /// A **gateway bootstrap token** for user `"owner"` (RFC-0043).
    ///
    /// Minted at spawn, before the daemon moves into its task. Authenticating
    /// with it yields `Principal::Gateway`: it may mint a session for a third
    /// party and nothing else (P1). Lets tests exercise the gateway credential
    /// without running a real sidecar process.
    pub gateway_token: String,
    /// The daemon's runtime, for reaching state the IPC surface deliberately
    /// does not expose — notably store-addressed access (RFC-0058).
    pub runtime: std::sync::Arc<kotton_device::DeviceRuntime>,

    /// Which users the daemon has resident. Reaching a user's runtime goes
    /// through here now, not through [`Self::runtime`] (RFC-0080 step 6).
    pub users: kuserd::residency::UserRegistry,
    /// Temporary directory that holds the daemon's databases.
    /// Kept alive for the lifetime of `TestEnv`.
    _base: TempDir,
    daemon_task: JoinHandle<std::io::Result<()>>,
    /// The daemon itself, kept so [`Drop`] can close its pools.
    ///
    /// Aborting `daemon_task` alone does not: an aborted future never reaches
    /// the teardown at the end of `run`, so every pool it holds stays live until
    /// the process exits.
    /// The in-process daemon itself, for what it would do outside IPC — the
    /// environment it hands a sidecar at spawn, for one.
    pub daemon: Arc<DeviceDaemon>,
    /// The runtime the daemon was built and run on. Taken in [`Drop`] so its
    /// teardown can block without stalling the test's own runtime.
    daemon_rt: Option<tokio::runtime::Runtime>,
    /// The prefix this environment's daemon threads carry, so a teardown check
    /// can tell them from every other test's in a parallel run.
    daemon_thread_prefix: String,
    /// Where a test that stands up this machine's `kdeviced` puts it: the door
    /// this daemon's `Supervision` names, by [`door_in`] on [`Self::base_dir`].
    /// Nothing listens there unless a test starts one.
    pub kdeviced: IpcEndpoint,
    /// Every door this environment made — its daemon's, [`Self::kdeviced`], and
    /// each one [`Self::door`] handed out. Dropped in [`Drop`] after the daemon
    /// has shut down, which removes whichever had to go outside the tempdir.
    doors: std::sync::Mutex<Vec<Door>>,
}

impl TestEnv {
    /// Spin up an isolated daemon and return a connected client.
    ///
    /// Apps run in the mock runner: every test here that launches one wants a
    /// scripted guest.
    ///
    /// Panics if the daemon cannot be initialised or the client cannot connect
    /// — not expected in normal CI runs.
    pub async fn spawn() -> Self {
        Self::spawn_with_runner(PathBuf::from(mock_runner_bin())).await
    }

    /// A daemon pointed at `relay_url`, said **to that daemon**.
    ///
    /// The relay used to be named with `std::env::set_var("KOTTON_RELAY_URL")`
    /// around the spawn. That variable is process-wide and read at construction,
    /// and this suite constructs daemons concurrently in one process, so the
    /// window between setting it and clearing it was a window in which *any*
    /// other test's daemon picked the value up — and in which this one could
    /// miss it. `#[serial]` on the five tests that set it kept them apart from
    /// each other and from nothing else
    /// (`TASK-a-process-global-relay-url-is-shared-by-tests-that-run-in-parallel`).
    ///
    /// The base dir, the endpoint, the secrets store and the runner are all
    /// handed to the daemon for the same reason. This is the last of them.
    pub async fn spawn_at_relay(relay_url: &str) -> Self {
        Self::spawn_placed(
            PathBuf::from(mock_runner_bin()),
            Placement::Isolated,
            RelayChoice::At(relay_url.to_string()),
        )
        .await
    }

    /// A daemon with **no** relay named, stated. Nothing reads a relay from
    /// the process environment since 2026-09-29, so a bare spawn is the same
    /// daemon; this is the constructor a test asserting *no relay* says so with.
    pub async fn spawn_without_relay() -> Self {
        Self::spawn_placed(
            PathBuf::from(mock_runner_bin()),
            Placement::Isolated,
            RelayChoice::None,
        )
        .await
    }

    /// Spin up an isolated daemon that runs apps with the binary at `runner`.
    ///
    /// Handed to the daemon at construction rather than through `KOTTON_RUNNER`,
    /// which this harness set process-wide until 2026-09-05. That was safe only
    /// while every test wanted the same binary: the variable was read at each
    /// spawn, so the first test to want a different runner would have changed
    /// which sandbox every concurrently running test got.
    async fn spawn_with_runner(runner: PathBuf) -> Self {
        Self::spawn_placed(runner, Placement::Isolated, RelayChoice::Configured).await
    }

    /// Spin up a daemon a **`kotton` subprocess can find on its own**, given only
    /// `KOTTON_BASE_DIR` in its environment.
    ///
    /// [`Placement::Isolated`] puts the socket at a unique path the test hands to
    /// `connect_to`, which is right for every test that drives the daemon through
    /// a library client. A CLI process does not get handed anything: it calls
    /// `daemon_socket_path(kuserd_ipc_name())` and goes where that says. So this
    /// variant puts the socket exactly there — see [`Placement::CliDiscoverable`]
    /// for the derivation and what has to be true of the child's environment.
    ///
    /// Pair it with [`cli::Cli`], which builds that environment.
    pub async fn spawn_cli_reachable() -> Self {
        Self::spawn_placed(
            PathBuf::from(mock_runner_bin()),
            Placement::CliDiscoverable,
            RelayChoice::Configured,
        )
        .await
    }

    async fn spawn_placed(runner: PathBuf, placement: Placement, relay: RelayChoice) -> Self {
        let base = tempfile::tempdir().expect("create tempdir");

        // Unique IPC name per test so parallel invocations don't collide.
        let unique = Uuid::new_v4().simple().to_string();

        #[cfg(windows)]
        let endpoint = IpcEndpoint::NamedPipe(match placement {
            // On Windows `connect()` uses the bare name as the pipe name, so the
            // child is pointed at it with `KUSERD_IPC_NAME` and the base dir plays
            // no part in finding it.
            Placement::CliDiscoverable => cli::pipe_name(&unique),
            Placement::Isolated => format!("kotton-test-{unique}"),
        });

        #[cfg(windows)]
        let door = Door::pipe(match &endpoint {
            IpcEndpoint::NamedPipe(name) => name.clone(),
        });

        #[cfg(unix)]
        let door = match placement {
            Placement::CliDiscoverable => discoverable_door(base.path()),
            Placement::Isolated => isolated_door(base.path(), &unique),
        };
        #[cfg(unix)]
        let endpoint = door.clone();

        // `kdeviced` is named **in this base**, never the machine's: a daemon's
        // unlock proves the person's own operator key to `kdeviced`
        // (`TASK-this-devices-operators-box-speaks-to-kdeviced-under-the-persons-own-key`),
        // and on a machine whose own `kdeviced` runs with nobody enrolled, a test's
        // key would otherwise become that machine's first operator. A test that
        // stands one up reads the same door from `TestEnv::kdeviced`.
        #[cfg(unix)]
        let kdeviced_door = door_in(base.path(), "kdeviced.sock");
        #[cfg(windows)]
        let kdeviced_door = Door::pipe(format!("kotton-test-kdeviced-{}", Uuid::new_v4().simple()));
        let kdeviced = kdeviced_door.clone();

        let secrets: Arc<dyn SecretsStore + Send + Sync> = Arc::new(MemorySecrets::new());

        // The daemon gets its **own** runtime, and is both built and run on it.
        //
        // Not incidental — it is what makes an ordered teardown possible at all.
        // `Drop` cannot await, so it has to block; if the daemon's tasks lived on
        // the test's runtime, blocking there would stop the very tasks the
        // teardown awaits, and drop would hang forever.
        //
        // Construction happens on it too. `new` spawns the device event log, so
        // building on the test's runtime would strand that task there and leave
        // exactly the leak this is meant to close.
        // Named per environment, so a thread can be attributed to *this*
        // daemon. The suite runs its tests in parallel in one process, so a
        // count of "threads that appeared while my daemon ran" is really a
        // count of everybody's — which is what made
        // `no_daemon_thread_outlives_a_test_env` fail in a full run and pass
        // alone. A name is what turns that back into a measurement.
        static ENVS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let env_id = ENVS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let daemon_thread_prefix = format!("kotton-env-{env_id}");
        let daemon_rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name(daemon_thread_prefix.clone())
            .enable_all()
            .build()
            .expect("daemon runtime");

        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let daemon_task = daemon_rt.spawn({
            let base_path = base.path().to_owned();
            let endpoint = endpoint.clone();
            let secrets = Arc::clone(&secrets);
            let kdeviced = kdeviced.clone();
            async move {
                let daemon = Arc::new(
                    DeviceDaemon::new_supervised(
                        base_path,
                        endpoint,
                        secrets,
                        relay,
                        kuserd::agent::Supervision {
                            principal: std::env::var("KOTTON_USER_DID").ok(),
                            kdeviced: Some(kdeviced),
                        },
                    )
                    .await
                    .expect("DeviceDaemon::new_supervised")
                    .with_runner(runner),
                );
                // Hand the caller its handle before serving, so it can mint the
                // gateway token and reach the runtime while `run` is blocking.
                ready_tx.send(Arc::clone(&daemon)).ok();
                daemon.run().await
            }
        });
        let daemon: Arc<DeviceDaemon> = ready_rx.await.expect("daemon constructed");

        let gateway_token = daemon.mint_gateway_bootstrap_token("owner");
        let runtime = daemon.runtime();
        let users = daemon.users();

        // Poll until the daemon's IPC listener accepts a connection, rather than
        // sleeping a fixed interval.  A fixed sleep is unreliable under a fully
        // parallel `cargo test`: the suite oversubscribes the CPU, so a freshly
        // spawned daemon can take far longer than any fixed guess to bind its
        // listener.  Retrying on a generous deadline returns the instant the
        // daemon is ready (no cost on the happy path) and stays green under load.
        let client = {
            let deadline = std::time::Instant::now() + Duration::from_secs(30);
            loop {
                match KottonClient::connect_to(endpoint.clone()).await {
                    Ok(client) => break client,
                    Err(_) if std::time::Instant::now() < deadline => {
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                    Err(e) => panic!("test daemon did not accept a connection within 30s: {e}"),
                }
            }
        };

        TestEnv {
            client,
            endpoint,
            secrets,
            base_dir: base.path().to_owned(),
            gateway_token,
            runtime,
            users,
            daemon,
            daemon_rt: Some(daemon_rt),
            daemon_thread_prefix,
            kdeviced,
            doors: std::sync::Mutex::new(vec![door, kdeviced_door]),
            _base: base,
            daemon_task,
        }
    }
}

impl TestEnv {
    /// A door for a socket named `file` on this machine's base, by [`door_in`] —
    /// for a test that stands up a second daemon beside this one. The environment
    /// keeps it and removes it on drop.
    #[cfg(unix)]
    pub fn door(&self, file: &str) -> IpcEndpoint {
        let door = door_in(&self.base_dir, file);
        let endpoint = door.clone();
        self.doors.lock().unwrap_or_else(|e| e.into_inner()).push(door);
        endpoint
    }

    /// Spawn a daemon and authenticate the connection as a default user.
    ///
    /// Control-plane operations (app/schema/handler management, roles, grants)
    /// now require an authenticated session (security audit C2 — the control
    /// plane no longer dispatches session-less). Tests that exercise those ops
    /// but are not themselves about the auth boundary use this so the connection
    /// carries a session, mirroring production where the CLI / kuid authenticate
    /// before issuing control-plane requests.
    pub async fn spawn_authed() -> Self {
        let mut env = Self::spawn().await;
        env.client
            .create_user("owner", TEST_PASSPHRASE)
            .await
            .expect("create_user (authenticates the connection)");
        env
    }

    /// [`Self::spawn_authed`] wired to the mock `kotton-runner` binary.
    pub async fn spawn_with_mock_runner_authed() -> Self {
        let mut env = Self::spawn_with_mock_runner().await;
        env.client
            .create_user("owner", TEST_PASSPHRASE)
            .await
            .expect("create_user (authenticates the connection)");
        env
    }

    /// Spin up an isolated daemon wired to the mock `kotton-runner` binary.
    ///
    /// The same as [`Self::spawn`] now that the mock is the default; kept as
    /// the name the app tests say what they mean with.
    ///
    /// Tests that **also** need to set `MOCK_RUNNER_MODE` (the `"error"` or
    /// `"exit"` modes) must use `#[serial_test::serial]` to prevent races
    /// with other tests — that variable is the mock's own, read by the child.
    pub async fn spawn_with_mock_runner() -> Self {
        Self::spawn().await
    }

    /// Put `user_id` into the state a **daemon restart** leaves them in: locked,
    /// with a resident store bound to no key.
    ///
    /// ## Why this exists
    ///
    /// Until 2026-09-09 nothing in this suite restarted a daemon, so the daemon
    /// under test was always one whose user store had been built *after* the key
    /// existed. No test had ever asked what happens in the state every real device
    /// is in every morning, and a defect lived in that gap for as long as the gap
    /// did: `UnlockWithPin` restored a user's operational roots and never rebuilt
    /// their store, so a restarted node reported a successful login and could not
    /// read the user's own data
    /// (`TASK-login-does-not-give-a-restarted-node-its-key-back`). It failed
    /// *quietly*, because every computed view over the membership set answers
    /// empty rather than erroring when the store cannot open.
    ///
    /// ## Why this models a restart rather than faking one
    ///
    /// Each step is the product's own mechanism, not a stub. `SealedCustody` holds
    /// the operational roots in this process's memory and nowhere else (RFC-0053
    /// step 4) — losing them on exit is the design, and the durable copy is the
    /// vault sealed under the daily credential. `lock_identity` is that loss
    /// without the exit. The reload then rebuilds the store with whatever CEK
    /// resolves now, which is none, and residency installs it (RFC-0080 step 6).
    ///
    /// What it does **not** model is a real process restart, so it cannot catch
    /// anything that depends on the process itself going away. One test that does
    /// restart a process would be worth having, and would be what proves this
    /// models it; that is a larger question than this helper
    /// (`TASK-the-suite-never-restarts-a-daemon`).
    ///
    /// ## Two ways to write this by hand and get it wrong
    ///
    /// Both were made in one sitting, and both produced a test that passed while
    /// asserting nothing. `delete_all_user_secrets` looks like it produces this
    /// state and does not — the roots are in memory custody, not the platform
    /// store. And `reload_user_runtime` *returns* a store rather than installing
    /// one, so dropping the result leaves the stale keyed store resident and every
    /// read succeeds. This asserts its way past both: it panics if the roots were
    /// not in custody to begin with, so it can never silently do nothing.
    ///
    /// The caller should still assert that a read of that user's data now fails
    /// before testing whatever is meant to fix it. Every defect this gap hides
    /// looks like success from the outside.
    pub async fn lock_as_a_restart_would(&self, user_id: &str) {
        lock_as_a_restart_would(&self.daemon, user_id).await;
    }
}

/// [`TestEnv::lock_as_a_restart_would`] for a daemon a test built itself.
///
/// The two-daemon tests — an enrolment, a threshold signature — construct their
/// daemons directly rather than through [`TestEnv`], and the restarted state is
/// no less real for them. One body, so the recipe and its warnings live once:
/// the method above is this call with the env's own daemon.
/// (`TASK-a-locked-node-reports-no-co-signers-rather-than-that-it-is-locked`
/// is the first caller that needed it outside a `TestEnv`.)
pub async fn lock_as_a_restart_would(daemon: &DeviceDaemon, user_id: &str) {
    let runtime = daemon.runtime();
    assert!(
        runtime.custody().lock_identity(user_id),
        "'{user_id}' held no operational roots in memory custody, so locking \
         them models nothing — the state under test was never set up"
    );
    let cold = kotton_device::users::DeviceUsers::reload_user_runtime(runtime.as_ref(), user_id)
        .await
        .expect("rebuild the resident user as a cold daemon would load it");
    daemon.users().insert(user_id.to_string(), cold);

    // **And the rest of a restart.** The two lines above are the object store's; the
    // `agent.db` pool and the `records.db` store are cached separately, keyed and open,
    // and a read that finds them there never asks whether a key still resolves. A
    // process that had really restarted would hold none of them.
    //
    // Measured twice. 2026-09-17: without the `agent.db` half, `app_list` answered
    // with both bundled apps *after* this helper ran, so a test asserting a locked
    // machine cannot name its own shell passed while asserting nothing. 2026-09-25:
    // without the `records.db` half, the inbox and the unread count answered the same
    // way. Same shape as the two mistakes this doc already warns about, one cache
    // further out each time — which is the argument for a test that restarts a real
    // process (`TASK-the-suite-never-restarts-a-daemon`) rather than another warning.
    daemon.evict_open_databases(user_id).await;
}

impl Drop for TestEnv {
    fn drop(&mut self) {
        // Abort first so the accept loop stops taking new work, then close what
        // the daemon holds. The abort alone was the whole of this impl, and an
        // aborted future never reaches the teardown at the end of `run` — so
        // every pool stayed live until process exit, leaving ~100 threads alive
        // when libc ran the atexit handlers
        // (TASK-integration-test-segfault-at-exit).
        self.daemon_task.abort();

        let doors = std::mem::take(self.doors.get_mut().unwrap_or_else(|e| e.into_inner()));
        let Some(rt) = self.daemon_rt.take() else {
            drop(doors);
            return;
        };
        let daemon = Arc::clone(&self.daemon);

        // Blocking happens on a scratch thread, and on the daemon's **own**
        // runtime — never the test's. `block_on` here parks this thread while
        // that runtime's workers drive the teardown, which is why the awaits
        // inside `shutdown` can finish. Doing it on the test's current-thread
        // runtime deadlocks: the thread being blocked is the only one that could
        // run the tasks being awaited.
        let handed_back = std::thread::spawn(move || {
            rt.block_on(daemon.shutdown());
            // Then stop the runtime itself, bounded: a task that ignores its
            // abort must not hang the suite.
            rt.shutdown_timeout(std::time::Duration::from_secs(5));
        })
        .join();
        if handed_back.is_err() {
            eprintln!("TestEnv::drop: daemon shutdown thread panicked");
        }
        drop(doors);
    }
}

// ── Streamed pairing (RFC-0040) ───────────────────────────────────────────────
// Moved here 2026-08-22 from `enroll_threshold_sign.rs`, whose module doc already
// called it "the shared `enroll_streamed` helper" while it was in fact private to
// that one binary. `introduction.rs` needs the same ceremony to put two nodes in
// one key domain, and duplicating 80 lines of ceremony driving was the alternative.

/// Keep pairing on loopback (no LAN bind, no mDNS) so the OS firewall never prompts
/// during these single-host tests. Set once, before any daemon binds a listener.
pub fn pair_local_only() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        #[allow(unsafe_code)] // env::set_var is unsafe in Rust 1.81+; idempotent, set once
        unsafe {
            std::env::set_var("KOTTON_PAIR_LOCAL_ONLY", "1");
        }
    });
}
/// Run the RFC-0040 streamed pairing ceremony between two in-process daemons,
/// auto-confirming the six-digit SAS on both sides. Replaces the retired
/// `node_enroll`/`node_join` triple used to set up a two-node identity. Each device
/// announces its own name (`device-e` issuer, `device-n` joiner); returns both
/// clients (the joiner now authenticated) and the issuer's view of the joiner.
///
/// There is no port to pass: the issuer's bootstrap listener is bound where the OS
/// says, and the code it advertises carries the port.
pub async fn enroll_streamed(
    client_e: KottonClient,
    client_n: KottonClient,
    user: &str,
    joiner_name: &str,
    posture: Posture,
) -> (KottonClient, KottonClient, PairedNode) {
    enroll_streamed_as(client_e, client_n, user, "device-e", joiner_name, posture).await
}

/// [`enroll_streamed`], with the name the issuing device announces. Two
/// people's devices enrolling one vault must announce different names today
/// (`TASK-two-tenants-whose-devices-share-a-name-unpair-each-other-at-a-vault`).
///
/// Each side's stream is read by [`issued`] and [`joined`], until the door
/// ends it; when a side fails, the panic says both sides' words.
pub async fn enroll_streamed_as(
    client_e: KottonClient,
    mut client_n: KottonClient,
    user: &str,
    issuer_name: &str,
    joiner_name: &str,
    posture: Posture,
) -> (KottonClient, KottonClient, PairedNode) {
    pair_local_only();
    let issuer_name = issuer_name.to_string();
    let (code_tx, code_rx) = oneshot::channel::<String>();
    let user_i = user.to_string();
    let issuer = tokio::spawn(async move {
        // Port 0: the issuer's daemon binds what the OS gives it and says it
        // in the code. A port picked here and bound there was a race with every
        // other test binding one meanwhile, and lost under parallel load (#110).
        let rx = client_e
            .device_add_stream(&user_i, Some(&issuer_name), 30, 0, posture)
            .await
            .expect("device_add_stream");
        let (client, user) = (&client_e, user_i.as_str());
        let node = issued(rx, code_tx, move |token| async move {
            client.pair_confirm_code(user, &token, true).await.expect("issuer confirm");
        })
        .await;
        (client_e, node)
    });
    let user_j = user.to_string();
    let joiner_name = joiner_name.to_string();
    let joiner = tokio::spawn(async move {
        let Ok(code) = code_rx.await else {
            panic!("no code reached the joiner: the issuer's stream gave none (the issuer says why)");
        };
        let rx = client_n
            .device_join_stream(&user_j, &code, Some(&joiner_name))
            .await
            .expect("device_join_stream");
        let (client, user) = (&client_n, user_j.as_str());
        let session = joined(rx, move |token| async move {
            client.pair_confirm_code(user, &token, true).await.expect("joiner confirm");
        })
        .await;
        // The join issues this device a session (it authenticated by completing
        // the FROST ceremony). Bind it to the client so downstream calls act as
        // the joined identity — mirrors what the retired `node_join` SDK method
        // did on completion.
        if let Some(token) = session {
            client_n.authenticate(&token).await.expect("bind joined session");
        }
        client_n
    });
    // Both sides, then one failure that says each: a joiner that fails mid-way
    // leaves the issuer waiting out its window, so the first side to fail is not
    // always the one that says why.
    match tokio::join!(issuer, joiner) {
        (Ok((client_e, node_n)), Ok(client_n)) => (client_e, client_n, node_n),
        (issuer, joiner) => panic!(
            "the ceremony did not complete\n  issuer: {}\n  joiner: {}",
            side_said(issuer.map(drop)),
            side_said(joiner.map(drop)),
        ),
    }
}

/// **The issuing side of a device ceremony, read until the door ends its
/// stream** (#110): the code is handed to `code_tx`, the six digits are
/// confirmed through `confirm` with the frame's token, and the result is the
/// paired node. Nothing else is acted on.
///
/// Which frame is last is the door's to say by ending the stream
/// (`kuserd::agent::streamed`), not this reader's to guess by name. Every
/// frame it does not act on is held, in order, and said ([`Unread`]) when it
/// fails: when the stream ends before `PairAdvertising` or without
/// `PairingComplete`, or when anything follows the result. A loop that broke
/// on the result and dropped the rest with `_ => {}` once lost the one frame
/// that said why a stream ended before it advertised a code.
async fn issued<F: std::future::Future<Output = ()>>(
    mut rx: tokio::sync::mpsc::Receiver<UserResponse>,
    code_tx: oneshot::Sender<String>,
    confirm: impl Fn(String) -> F,
) -> PairedNode {
    let mut code_tx = Some(code_tx);
    let mut node = None;
    let mut unread = Unread::default();
    while let Some(frame) = rx.recv().await {
        if node.is_some() {
            unread.hold(&frame);
            panic!("the issuer's stream said more after PairingComplete: {unread}");
        }
        match frame {
            UserResponse::PairAdvertising { code, .. } => match code_tx.take() {
                Some(tx) => {
                    let _ = tx.send(code.expose().to_string());
                }
                None => panic!("the issuer's stream advertised a second code; before it: {unread}"),
            },
            UserResponse::PairShowCode { token, .. } => confirm(token.expose().to_string()).await,
            UserResponse::PairingComplete { node: n, .. } => node = Some(n),
            not_this_steps => unread.hold(&not_this_steps),
        }
    }
    match (code_tx, node) {
        (Some(_), _) => panic!("the issuer's stream ended before PairAdvertising; it said: {unread}"),
        (None, None) => panic!("the issuer's stream ended without PairingComplete; after its code it said: {unread}"),
        (None, Some(node)) => node,
    }
}

/// **The joining side, read the same way as [`issued`]**: the six digits are
/// confirmed through `confirm`, and the result is the session the join issued
/// this device, if any. The stream must end after a `PairingComplete` and
/// nothing past it; any other end is said with the frames not acted on.
async fn joined<F: std::future::Future<Output = ()>>(
    mut rx: tokio::sync::mpsc::Receiver<UserResponse>,
    confirm: impl Fn(String) -> F,
) -> Option<String> {
    let mut completed = None;
    let mut unread = Unread::default();
    while let Some(frame) = rx.recv().await {
        if completed.is_some() {
            unread.hold(&frame);
            panic!("the joiner's stream said more after PairingComplete: {unread}");
        }
        match frame {
            UserResponse::PairShowCode { token, .. } => confirm(token.expose().to_string()).await,
            UserResponse::PairingComplete { session_token, .. } => {
                completed = Some(session_token.map(|t| t.expose().to_string()));
            }
            not_this_steps => unread.hold(&not_this_steps),
        }
    }
    completed.unwrap_or_else(|| panic!("the joiner's stream ended without PairingComplete; it said: {unread}"))
}

/// The frames a ceremony step did not act on, in order, each as
/// [`kotton_wire::ipc::answer_said`] says it: what the step says when it fails.
#[derive(Default)]
struct Unread(Vec<String>);

impl Unread {
    fn hold(&mut self, frame: &UserResponse) {
        self.0.push(match frame {
            // `answer_said` has no sentence for a ceremony's own failure; its
            // reason is the sentence.
            UserResponse::PairFailed { reason } => format!("PairFailed: {reason}"),
            other => kotton_wire::ipc::answer_said(other),
        });
    }
}

impl std::fmt::Display for Unread {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0.as_slice() {
            [] => f.write_str("no frame at all"),
            said => write!(f, "[{}]", said.join("] [")),
        }
    }
}

/// How one side of a ceremony ended: `completed`, or the words it failed with.
fn side_said(ended: Result<(), tokio::task::JoinError>) -> String {
    match ended {
        Ok(()) => "completed".to_string(),
        Err(e) if e.is_panic() => {
            let payload = e.into_panic();
            payload
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| payload.downcast_ref::<&str>().map(|s| s.to_string()))
                .unwrap_or_else(|| "panicked with no message".to_string())
        }
        Err(e) => e.to_string(),
    }
}

/// One `surface_open` as [`NullAppHost`] records it: `(handle, app_id, role, edge, title)`.
pub type OpenedSurface = (
    kotton_wire::SurfaceHandle,
    String,
    kotton_wire::SurfaceRole,
    Option<kotton_wire::PanelEdge>,
    String,
);

/// An [`AppHost`] that records surface traffic and publishes into a bus nobody
/// reads.
///
/// For testing launch paths where what matters is *whether* a surface was
/// opened and what was painted onto it, not where the pixels went. The real
/// `DaemonAppHost` needs a live `SurfaceProxy` and an event bus wired into a
/// daemon; a launch-path test needs neither.
#[derive(Default)]
pub struct NullAppHost {
    pub events: std::sync::OnceLock<Arc<kotton_diag::service::EventBus>>,
    /// `(handle, app_id, role, edge, title)` for each `surface_open`, in order.
    ///
    /// The `edge` is `Some` only for a `Panel` and is the whole of what a
    /// designated app may say about where a strip goes (RFC-0087 stage 3c) — an
    /// anchor the host places from, never a position the app named.
    ///
    /// The `app_id` is here because the *host* is told it (RFC-0087) — it is
    /// what a real host records so a keystroke can be routed back. The
    /// compositor is not told it, and this double is on the host's side of that
    /// line.
    pub opened: std::sync::Mutex<Vec<OpenedSurface>>,
    /// Each patch committed, in order, against the surface it went to.
    pub committed: std::sync::Mutex<Vec<(kotton_wire::SurfaceHandle, Vec<u8>)>>,
    /// Each surface a guest asked to have raised, in order.
    pub raised: std::sync::Mutex<Vec<kotton_wire::SurfaceHandle>>,
    /// Each title a guest gave one of its surfaces, in order, with the surface it named.
    pub titled: std::sync::Mutex<Vec<(kotton_wire::SurfaceHandle, String)>>,
    /// What [`AppHost::surface_windows`] should answer — the app stack, as the host holds
    /// it, front-most last (RFC-0087 stage 3b).
    pub windows: std::sync::Mutex<Vec<kotton_wire::HostWindow>>,
    /// Each window a designated app asked to have restored, in order.
    pub restored: std::sync::Mutex<Vec<kotton_wire::SurfaceHandle>>,
    /// Each surface the daemon closed, in order.
    ///
    /// Recorded rather than dropped, because *what a failed launch takes back
    /// down* is only checkable from here: `surface_close` was an empty body, so
    /// a launch that left a window open for a process that never ran looked
    /// exactly like one that cleaned up (RFC-0087 stage 2).
    pub closed: std::sync::Mutex<Vec<kotton_wire::SurfaceHandle>>,
    /// What [`AppHost::registered_users`] should answer.
    pub users: Vec<String>,
    /// Which binary [`AppHost::runner`] should name. `None` is the mock runner,
    /// which is what a launch-path test wants: it answers the protocol without
    /// compiling or running a guest.
    ///
    /// A test that means to run a **real** component has to set this. Setting
    /// `KOTTON_RUNNER` does not do it: `spawn_and_present` reads `host.runner()`,
    /// and has since the runner moved onto this trait on 2026-09-05 —
    /// *"stated once by the host rather than read from the environment at each
    /// spawn"*. A test still pointing at the environment gets the mock, a launch
    /// that succeeds, and nothing painted.
    pub runner: Option<std::path::PathBuf>,
}

/// A keychain that holds nothing.
///
/// `AppHost::secrets` exists for one job at launch — re-minting a grant envelope
/// that predates the signed `app_id` binding (`DEC-0052`) — and a store with no
/// identity key makes that a no-op, which is what a null host should do.
pub struct NullSecrets;

impl kotton_sys::secret::SecretsStore for NullSecrets {
    fn get_secret(&self, _key: &str) -> kotton_sys::secret::SecretsResult<Option<String>> {
        Ok(None)
    }
    fn set_secret(&self, _key: &str, _value: &str) -> kotton_sys::secret::SecretsResult<()> {
        Ok(())
    }
    fn delete_secret(&self, _key: &str) -> kotton_sys::secret::SecretsResult<()> {
        Ok(())
    }
}

#[async_trait::async_trait]
impl kotton_app::daemon::apps::AppHost for NullAppHost {
    fn secrets(&self) -> &dyn kotton_sys::secret::SecretsStore {
        &NullSecrets
    }

    /// No store behind this host, so no roots — which is a fact about this
    /// host and not an empty set of roots (RFC-0071 R11), and since 2026-09-24
    /// a cause the occupant is told rather than a `None` the launch turned
    /// into an empty list (`TASK-a-roots-failure-is-drawn-as-no-roots`).
    fn user_roots(
        &self,
        _: &std::path::Path,
        _: &str,
        _: &str,
    ) -> Result<Vec<kotton_wire::runner::RunnerRoot>, kotton_wire::runner::RootsUnread> {
        Err(kotton_wire::runner::RootsUnread::StoreNotLoaded)
    }

    /// A null host stands for one whose person is in with keys: the launches
    /// these tests drive are about bodies, grants and surfaces, not custody.
    fn keys_loaded(&self, _: &str) -> bool {
        true
    }

    /// No store behind this host, so no person's tree: a guest's `files`
    /// calls are told the files are not open here.
    fn personal_tree(
        &self,
        _: &str,
    ) -> Option<Arc<dyn kotton_app::daemon::apps::PersonalTree>> {
        None
    }

    /// The mock, like the daemon these tests spawn: a null host still names
    /// which process would run an app, because the trait says a host does.
    fn runner(&self) -> &std::path::Path {
        match &self.runner {
            Some(p) => p.as_path(),
            None => std::path::Path::new(mock_runner_bin()),
        }
    }

    fn events(&self) -> &Arc<kotton_diag::service::EventBus> {
        self.events
            .get_or_init(|| Arc::new(kotton_diag::service::EventBus::new(64)))
    }

    fn registered_users(&self) -> Vec<kotton_app::daemon::apps::RegisteredUser> {
        self.users
            .iter()
            .map(|user_id| kotton_app::daemon::apps::RegisteredUser {
                user_id: user_id.clone(),
                display_name: None,
            })
            .collect()
    }

    async fn surface_open(
        &self,
        handle: kotton_wire::SurfaceHandle,
        app_id: &str,
        spec: kotton_wire::SurfaceSpec,
    ) {
        self.opened.lock().unwrap().push((
            handle,
            app_id.to_string(),
            spec.role,
            spec.edge,
            spec.title,
        ));
    }

    async fn surface_commit(&self, handle: kotton_wire::SurfaceHandle, patch: Vec<u8>) {
        self.committed.lock().unwrap().push((handle, patch));
    }

    async fn surface_close(&self, handle: kotton_wire::SurfaceHandle) {
        self.closed.lock().unwrap().push(handle);
    }

    async fn surface_raise(&self, handle: kotton_wire::SurfaceHandle) {
        self.raised.lock().unwrap().push(handle);
    }

    /// Recorded **nowhere**, and deliberately.
    ///
    /// Nothing in this suite drives `surface.request-size`: the mock runner never emits
    /// the verb, and the one test that launches the real shell reaches the welcome
    /// screen, which has no panels to ask a width for. A recorder field no test reads is
    /// a fixture pretending to be coverage, which is what this was for one commit.
    ///
    /// **The audit that decides whether this is ever reached is tested** — against a host
    /// that does record — in `core/app`'s own
    /// `daemon::apps::host_call_tests::a_resize_reaches_the_host_only_for_a_surface_this_instance_holds`.
    /// A suite test that needs the record adds the field and the assertion on it in the
    /// same commit.
    async fn surface_resize(
        &self,
        _handle: kotton_wire::SurfaceHandle,
        _width: u32,
        _height: u32,
    ) {
    }

    /// Recorded here, unlike the size above, because the one test that launches the real
    /// shell does reach it: a shell window says what it is through `surface.set-title` as
    /// it opens, so a suite that could not see the call could not tell a titled window
    /// from an untitled one.
    async fn surface_set_title(&self, handle: kotton_wire::SurfaceHandle, title: String) {
        self.titled.lock().unwrap().push((handle, title));
    }

    /// The windows this null host says there are.
    ///
    /// Settable rather than fixed, because what the window-list tests are about is the
    /// translation between the host's view and the designated instance's — which needs a
    /// host that has something to translate (RFC-0087 stage 3b).
    async fn surface_windows(&self) -> Vec<kotton_wire::HostWindow> {
        self.windows.lock().unwrap().clone()
    }

    /// Each window a designated app asked to have brought back, in order.
    async fn surface_restore(&self, handle: kotton_wire::SurfaceHandle) {
        self.restored.lock().unwrap().push(handle);
    }
}


#[cfg(all(test, unix))]
mod door_tests {
    use super::*;

    /// A base directory long enough that `<base>/daemon-<32 hex>.sock` does not fit
    /// `sun_path` — the shape `tempfile::tempdir()` returns under a long `TMPDIR`.
    /// The guard removes it.
    fn long_base() -> (TempDir, PathBuf) {
        let guard = tempfile::tempdir().expect("tempdir");
        let base = guard.path().join("d".repeat(95));
        std::fs::create_dir_all(&base).expect("create the long directory");
        (guard, base)
    }

    /// An `Isolated` daemon under a long `TMPDIR` used to fail after a 30 s
    /// connection timeout with "path must be shorter than SUN_LEN"
    /// (`TASK-a-suite-daemon-placed-isolated-cannot-bind-under-a-long-tmpdir`).
    /// Bound here directly, so the failure is the kernel's answer and not a timeout.
    #[test]
    fn an_isolated_door_binds_under_a_long_tmpdir() {
        let (_guard, base) = long_base();
        let unique = Uuid::new_v4().simple().to_string();
        let door = isolated_door(&base, &unique);
        let bound = std::os::unix::net::UnixListener::bind(door.socket());
        bound.unwrap_or_else(|e| {
            panic!(
                "an Isolated door under a {}-byte base did not bind at {} ({} bytes): {e}",
                base.as_os_str().len(),
                door.socket().display(),
                door.socket().as_os_str().len(),
            )
        });
    }

    /// A door that had to leave its base is a fresh `0o700` directory, not a file
    /// in world-writable `/tmp`, and dropping the door removes it. One that fit
    /// removes its socket file. Before 2026-09-28 `unique_ipc`'s fallback was a bare
    /// `/tmp/kotton-test-<id>.sock` that nothing removed
    /// (`TASK-suite-tests-that-join-their-own-socket-path-cannot-bind-under-a-long-tmpdir`).
    #[test]
    fn a_door_is_private_when_it_leaves_its_base_and_goes_when_dropped() {
        use std::os::unix::fs::PermissionsExt as _;
        let (_guard, base) = long_base();
        let door = door_in(&base, "kotton-test-long.sock");
        let dir = door.dir_outside_base.clone().expect("a 95-byte base does not fit; the door leaves it");
        assert!(door.socket().starts_with("/tmp"), "{}", door.socket().display());
        let mode = std::fs::metadata(&dir).expect("the door's directory").permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "{} is {mode:o}", dir.display());
        let bound = std::os::unix::net::UnixListener::bind(door.socket()).expect("binds");
        drop(bound);
        drop(door);
        assert!(!dir.exists(), "{} outlived its door", dir.display());

        let short = tempfile::tempdir().expect("tempdir");
        let door = door_in(short.path(), "kotton-test-short.sock");
        if door.dir_outside_base.is_none() {
            let socket = door.socket().to_path_buf();
            drop(std::os::unix::net::UnixListener::bind(&socket).expect("binds"));
            drop(door);
            assert!(!socket.exists(), "{} outlived its door", socket.display());
        }
    }

    /// Under a long `TMPDIR` a CLI-discoverable daemon binds at the product's
    /// `/tmp/kotton-<hash>/` door, outside the test's tempdir. The door names that
    /// directory so [`TestEnv`]'s drop can remove it; inside the tempdir it names none.
    #[test]
    fn a_discoverable_door_outside_the_tempdir_names_its_directory() {
        let (_guard, base) = long_base();
        let door = discoverable_door(&base);
        assert!(!door.socket().starts_with(&base), "expected the /tmp fallback, got {}", door.socket().display());
        assert_eq!(door.dir_outside_base.as_deref(), door.socket().parent());

        let short = tempfile::tempdir().expect("tempdir");
        let door = discoverable_door(short.path());
        if door.socket().starts_with(short.path()) {
            assert_eq!(door.dir_outside_base, None);
        }
    }
}

// ── Install, approving everything ─────────────────────────────────────────────

/// Install an app approving exactly what its manifest asks for.
///
/// After the consent gate landed (security-audit **H2**,
/// `IDEA-install-consent-gate`), `app_install` takes the approved capability set
/// as a parameter: the daemon signs only what a caller named, so there is no
/// longer a call that means "sign whatever the app declared". That is the point
/// of the change, and it is also a nuisance for the several dozen tests here
/// that install an app in order to test something else entirely.
///
/// This helper runs the real two-phase ceremony — preview, then approve what came
/// back — so those tests exercise the production path rather than a shortcut
/// around it. It lives in the test harness and **not** on `KottonClient`,
/// deliberately: a production-side "approve everything" convenience is the
/// auto-mint growing back under a friendlier name.
#[async_trait::async_trait]
pub trait InstallApprovingAll {
    async fn app_install_approving_all(
        &mut self,
        user_id: &str,
        manifest_toml: String,
        wasm_bytes: Vec<u8>,
    ) -> std::io::Result<(String, String, Vec<String>)>;
}

#[async_trait::async_trait]
impl InstallApprovingAll for kotton::KottonClient {
    async fn app_install_approving_all(
        &mut self,
        user_id: &str,
        manifest_toml: String,
        wasm_bytes: Vec<u8>,
    ) -> std::io::Result<(String, String, Vec<String>)> {
        let preview = self
            .app_install_preview(user_id, manifest_toml.clone(), wasm_bytes.clone())
            .await?;
        self.app_install(user_id, manifest_toml, wasm_bytes, preview.requested, vec![])
            .await
    }
}

/// A port nothing is listening on right now.
pub fn free_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").expect("reserve a port");
    l.local_addr().expect("reserved port has an address").port()
}

// ── Spawning the fixture binaries ────────────────────────────────────────────

/// Path to the compiled `kotton-mock-runner`, or a failure that names every binary the
/// suite runs that is not built, with the commands that build them ([`bins`]).
pub fn mock_runner_bin() -> &'static str {
    bins::require(bins::Bin::MockRunner).to_str().expect("build.rs emits a UTF-8 path")
}

/// The same, for `kuserd`, which `two_node_transfer` spawns.
pub fn kuserd_bin() -> &'static str {
    bins::require(bins::Bin::Kuserd).to_str().expect("build.rs emits a UTF-8 path")
}

#[cfg(test)]
mod teardown_tests {
    use super::*;

    /// Dropping a `TestEnv` closes the daemon's pools before the test returns.
    ///
    /// This is the closing criterion for `TASK-integration-test-segfault-at-exit`,
    /// in the sharper form that record itself asked for. The original was "five
    /// consecutive full runs at exit 0" — the only bar available while the cause
    /// was unknown, and a bad one once it is: at the measured one-in-three crash
    /// rate, five clean runs happen by luck about 13% of the time, so passing it
    /// is weak evidence and failing it costs five full runs to learn.
    ///
    /// The mechanism was threads outliving `main`: `daemon_task.abort()` returns
    /// immediately, an aborted future never reaches the teardown at the end of
    /// `run`, so every pool stayed open and its blocking threads were still live
    /// when libc ran the atexit handlers. A closed pool is the observable end of
    /// that chain, and it is a fact about a single run rather than a probability.
    #[tokio::test]
    async fn the_daemons_pools_are_closed_when_a_test_env_drops() {
        let env = TestEnv::spawn().await;
        // Cloned out before the drop — the pool handle has to outlive the daemon
        // for there to be anything left to ask.
        let db = env.daemon.machine_db();
        assert!(!db.is_closed(), "a running daemon's pool should be open");

        drop(env);

        assert!(
            db.is_closed(),
            "TestEnv::drop left the machine pool open — the daemon's teardown did \
             not run, which is the leak that put ~100 live threads at exit()"
        );
        // Closed is not the same as empty. `is_closed` turns true the moment
        // `close()` is called, and sqlx-core 0.8.0's `close()` can return with a
        // connection still out, its worker thread still running SQLite — the
        // abort in `TASK-a-suite-run-aborts-at-exit-on-a-corrupted-heap-after-every-test-in-it-passed`.
        // `size()` counts the connections whose workers have not yet closed them.
        assert_eq!(
            db.size(),
            0,
            "TestEnv::drop returned with the machine pool closed but {} connection(s) \
             still open, each a worker thread that can outlive main",
            db.size()
        );
    }

    /// The threads this process holds right now, by kernel id and name.
    #[cfg(target_os = "linux")]
    fn live_threads() -> std::collections::BTreeMap<String, String> {
        std::fs::read_dir("/proc/self/task")
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| {
                let tid = e.file_name().to_string_lossy().into_owned();
                let name = std::fs::read_to_string(e.path().join("comm"))
                    .unwrap_or_default()
                    .trim()
                    .to_owned();
                (tid, name)
            })
            .collect()
    }

    /// The precondition of the exit-time crash, measured directly: no thread
    /// **this** daemon started is still running once its `TestEnv` is dropped.
    ///
    /// The pool test above asks about one handle; this asks about the thing the
    /// atexit handler races. It matters more than it did on 2026-08-27, because
    /// the handler is **still in the process**: `OPENSSL_cleanup` runs at exit
    /// from the system `libcrypto.so.3` that SQLCipher links (`libsqlite3-sys`
    /// 0.28's `bundled-sqlcipher`, for `core/record`), which removing
    /// `openssl-sys` from the Cargo graph did not change. A daemon thread left
    /// alive here is therefore not a leak but the crash, waiting on load
    /// (TASK-a-test-binary-segfaults-under-concurrency).
    ///
    /// **Attributed by name, not by when it appeared.** The suite runs its
    /// tests in parallel in one process, so "threads that appeared while my
    /// daemon ran" counts everybody's — which is why the first version of this
    /// passed alone and failed in a full run, reporting other environments'
    /// threads as leaks. `TestEnv` names its daemon runtime's threads per
    /// environment, and this counts exactly those. What it can no longer see is
    /// a thread the daemon starts on a runtime of its own; the pool test and
    /// the shutdown path cover that, and a name is worth more than a count that
    /// is only true when nothing else runs.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn no_daemon_thread_outlives_a_test_env() {
        let env = TestEnv::spawn().await;
        let prefix = env.daemon_thread_prefix.clone();
        let mine = || {
            live_threads()
                .into_iter()
                .filter(|(_, name)| name.starts_with(&prefix))
                .map(|(tid, name)| format!("{name} ({tid})"))
                .collect::<Vec<_>>()
        };
        assert!(
            !mine().is_empty(),
            "spawning a daemon started no thread named `{prefix}`; the measurement is not \
             measuring anything"
        );
        drop(env);

        // A thread told to stop may still be on its way out when `drop`
        // returns; one still here two seconds later is not.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        let survivors = loop {
            let survivors = mine();
            if survivors.is_empty() || std::time::Instant::now() > deadline {
                break survivors;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        };
        assert!(
            survivors.is_empty(),
            "thread(s) this daemon started outlived its TestEnv: {} — they are what \
             libcrypto's atexit handler races at exit()",
            survivors.join(", ")
        );
    }
}

/// What [`issued`] says when its stream ends without the frame its step needed
/// (#110). No daemon: each case is the frames a door could send, then its end.
#[cfg(test)]
mod ceremony_reader_tests {
    use super::*;

    /// The frames, then the end of the stream, read as the issuer reads them.
    /// Nothing here shows digits, so nothing is confirmed.
    async fn issuer_reads(frames: Vec<UserResponse>) -> (PairedNode, oneshot::Receiver<String>) {
        let (tx, rx) = tokio::sync::mpsc::channel(frames.len().max(1));
        for frame in frames {
            tx.send(frame).await.expect("the reader holds the stream");
        }
        drop(tx);
        let (code_tx, code_rx) = oneshot::channel();
        let node = issued(rx, code_tx, |_| async { unreachable!("no digits were shown") }).await;
        (node, code_rx)
    }

    /// A door that refuses before it advertises — the bootstrap listener could
    /// not be bound — answers its error and ends the stream. The issuer says
    /// the error, where it once said only that it did not complete.
    #[tokio::test]
    #[should_panic(
        expected = "the issuer's stream ended before PairAdvertising; it said: [open device-add listener: bootstrap QUIC bind failed: Address already in use (os error 98)]"
    )]
    async fn a_stream_that_ends_on_a_refusal_before_its_code_says_the_refusal() {
        issuer_reads(vec![UserResponse::Error {
            message: "open device-add listener: bootstrap QUIC bind failed: Address already in use (os error 98)".into(),
        }])
        .await;
    }

    /// A stream that ends with nothing in it says that nothing came.
    #[tokio::test]
    #[should_panic(expected = "the issuer's stream ended before PairAdvertising; it said: no frame at all")]
    async fn a_stream_that_ends_with_no_frame_says_none_came() {
        issuer_reads(Vec::new()).await;
    }

    /// After the code, a stream that ends without the result says every frame
    /// it passed by, in order, the ceremony's failure with its reason.
    #[tokio::test]
    #[should_panic(
        expected = "the issuer's stream ended without PairingComplete; after its code it said: [the answer was `PairConnected`, which this release has no sentence for; nothing more was asked of it] [PairFailed: the digits did not match]"
    )]
    async fn a_stream_that_ends_without_its_result_says_each_frame_it_passed_by() {
        issuer_reads(vec![
            UserResponse::PairAdvertising { code: kotton_wire::ipc::SecretText::new("a code"), expires_at: 0 },
            UserResponse::PairConnected,
            UserResponse::PairFailed { reason: "the digits did not match".into() },
        ])
        .await;
    }
}
