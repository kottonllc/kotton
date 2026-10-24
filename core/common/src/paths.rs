// SPDX-License-Identifier: AGPL-3.0-or-later
//! Centralized path constants and utilities for Kotton directory structure
//!
//! All path resolution for data directories, runtime socket directories, and
//! daemon sockets flows through this module.  Call-sites should never construct
//! platform paths inline — use the functions here so there is one source of truth.
//!
//! ## Key functions
//!
//! | Function | Purpose |
//! |----------|---------|
//! | [`base_dir`] | Per-user data directory (XDG / platform-native) |
//! | [`runtime_dir`] | Directory for IPC sockets (three-tier, `0o700`) |
//! | [`daemon_socket_path`] | Full socket path for a named daemon |
//! | [`daemon_socket_path_in`] | The same, for a daemon started with another environment |
//! | [`daemon_socket_fallback_dir`] | The `/tmp` directory a fallback door is in, to remove it |
//! | [`kdeviced_ipc_name`] | `kdeviced` socket name (`KDEVICED_IPC_NAME` override) |
//! | [`kdeviced_door`] | Where `kdeviced` answers: its name through the path rule |
//! | [`kuserd_ipc_name`] | `kuserd` dev-mode socket name (`KUSERD_IPC_NAME` override) |
//! | [`kuserd_ipc_name_in`] | The same, read from the environment a harness hands the daemon |
//! | [`pipe_path`] | The Windows pipe path a pipe name opens at |
//!
//! See `docs/decisions.md` — *IPC socket placement* for the security rationale
//! behind `runtime_dir`.

use anyhow::{anyhow, Result};
use std::path::PathBuf;

/// Get the per-user Kotton data directory.
///
/// Returns:
/// - Windows: `%LOCALAPPDATA%\Kotton`
/// - macOS:   `~/Library/Application Support/Kotton`
/// - Linux:   `$XDG_DATA_HOME/kotton` → `~/.local/share/kotton`
///
/// Override with `KOTTON_BASE_DIR` for dev isolation or CI:
/// ```sh
/// KOTTON_BASE_DIR=.kotton.dev cargo run --bin kuserd
/// ```
pub fn base_dir() -> Result<PathBuf> {
    base_dir_in(&process_env)
}

/// An environment to resolve a path in: a variable's value, or `None` when it is
/// unset or not UTF-8 — what `std::env::var(..).ok()` gives for this process.
///
/// The functions here that decide where a daemon's door is — [`base_dir`],
/// `runtime_dir`, `daemon_socket_path` and [`kuserd_ipc_name`] — each have an `_in`
/// form taking one, so a caller that starts a daemon with an environment of its
/// own — a unit's `EnvironmentFile=`, a test's scratch host — asks the same rule the daemon
/// asks, over the environment the daemon will have, instead of writing the rule out
/// again.
pub type Env<'a> = &'a dyn Fn(&str) -> Option<String>;

/// This process's environment, as an [`Env`].
fn process_env(key: &str) -> Option<String> {
    std::env::var(key).ok()
}

/// [`base_dir`], resolved in `env` rather than this process's environment.
pub fn base_dir_in(env: Env) -> Result<PathBuf> {
    if let Some(override_dir) = env("KOTTON_BASE_DIR") {
        return Ok(PathBuf::from(override_dir));
    }
    default_base_dir_in(env)
}

/// The platform-default base directory, **ignoring** `KOTTON_BASE_DIR`.
///
/// Exists so a caller can tell whether it is running against the default
/// install or an isolated one (dev, CI, a sideload) — which is what decides
/// whether OS-keychain entries use the legacy unscoped names or a
/// per-base-dir scope (`kotton_secret::OsSecrets::for_base_dir`).
pub fn default_base_dir() -> Result<PathBuf> {
    default_base_dir_in(&process_env)
}

fn default_base_dir_in(env: Env) -> Result<PathBuf> {
    #[cfg(target_os = "windows")]
    {
        let local_app_data =
            env("LOCALAPPDATA").ok_or_else(|| anyhow!("LOCALAPPDATA environment variable not set"))?;
        Ok(PathBuf::from(local_app_data).join("Kotton"))
    }

    #[cfg(target_os = "macos")]
    {
        let home = env("HOME").ok_or_else(|| anyhow!("HOME environment variable not set"))?;
        Ok(PathBuf::from(home)
            .join("Library")
            .join("Application Support")
            .join("Kotton"))
    }

    #[cfg(target_os = "linux")]
    {
        // XDG Base Directory Specification
        if let Some(xdg_data) = env("XDG_DATA_HOME") {
            return Ok(PathBuf::from(xdg_data).join("kotton"));
        }
        let home = env("HOME").ok_or_else(|| anyhow!("HOME environment variable not set"))?;
        Ok(PathBuf::from(home)
            .join(".local")
            .join("share")
            .join("kotton"))
    }

    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    {
        Err(anyhow!("Unsupported operating system"))
    }
}

/// Get the sessions directory (system-wide)
pub fn sessions_dir() -> Result<PathBuf> {
    Ok(base_dir()?.join("sessions"))
}

/// Get the users directory (system-wide)
pub fn users_dir() -> Result<PathBuf> {
    Ok(base_dir()?.join("users"))
}

/// Get a specific user's root directory (~/.kotton/users/{username})
pub fn user_dir(username: &str) -> Result<PathBuf> {
    Ok(users_dir()?.join(username))
}

/// Get a user's data directory (`{base}/users/{username}/data`)
pub fn user_vfs_dir(username: &str) -> Result<PathBuf> {
    Ok(user_dir(username)?.join("data"))
}

/// Get a user's contracts directory (`{base}/users/{username}/contracts`)
pub fn user_contracts_dir(username: &str) -> Result<PathBuf> {
    Ok(user_dir(username)?.join("contracts"))
}

/// Get the user directory — kept as `user_config_dir` for call-site compatibility.
/// The user config file is `users/<username>/config.toml` directly.
pub fn user_config_dir(username: &str) -> Result<PathBuf> {
    user_dir(username)
}

/// Get a user's apps directory (`{base}/users/{username}/apps`)
pub fn user_apps_dir(username: &str) -> Result<PathBuf> {
    Ok(user_dir(username)?.join("apps"))
}

/// Get a user's internal daemon directory (`{base}/users/{username}/.kotton`)
pub fn user_daemon_dir(username: &str) -> Result<PathBuf> {
    Ok(user_dir(username)?.join(".kotton"))
}

/// Get path to user's identity file (`{base}/users/{username}/.kotton/identity.json`)
pub fn user_identity_file(username: &str) -> Result<PathBuf> {
    Ok(user_daemon_dir(username)?.join("identity.json"))
}

/// Get path to user's events database (`{base}/users/{username}/.kotton/events.db`)
pub fn user_events_db(username: &str) -> Result<PathBuf> {
    Ok(user_daemon_dir(username)?.join("events.db"))
}

/// Get path to user's sessions database (`{base}/users/{username}/.kotton/sessions.db`)
pub fn user_sessions_db(username: &str) -> Result<PathBuf> {
    Ok(user_daemon_dir(username)?.join("sessions.db"))
}

/// Get path to user's log directory (`{base}/users/{username}/.kotton/logs`)
pub fn user_logs_dir(username: &str) -> Result<PathBuf> {
    Ok(user_daemon_dir(username)?.join("logs"))
}

/// Get daemon socket path (~/.kotton/users/{username}/.kotton/daemon.sock)
#[cfg(not(target_os = "windows"))]
pub fn user_daemon_socket_path(username: &str) -> Result<PathBuf> {
    Ok(user_daemon_dir(username)?.join("daemon.sock"))
}

/// Get the current OS username
pub fn os_username() -> Result<String> {
    #[cfg(target_os = "windows")]
    {
        std::env::var("USERNAME").map_err(|_| anyhow!("USERNAME environment variable not found"))
    }

    #[cfg(not(target_os = "windows"))]
    {
        std::env::var("USER")
            .or_else(|_| std::env::var("LOGNAME"))
            .map_err(|_| anyhow!("USER environment variable not found"))
    }
}

/// Get the session token cache file for a specific Kotton user.
/// Sessions stored at: `{base}/sessions/{username}.session`
///
/// Note: the SDK (`kotton_client::session_cache`) is the canonical writer/reader
/// of this file. This helper is provided for path-audit purposes.
pub fn session_file(kotton_username: &str) -> Result<PathBuf> {
    Ok(sessions_dir()?.join(format!("{}.session", kotton_username)))
}

/// List all session files (returns Kotton usernames)
pub fn list_sessions() -> Result<Vec<String>> {
    let sessions_dir = sessions_dir()?;

    if !sessions_dir.exists() {
        return Ok(Vec::new());
    }

    let mut usernames = Vec::new();

    for entry in std::fs::read_dir(sessions_dir)? {
        let entry = entry?;
        let path = entry.path();

        if path.extension().and_then(|s| s.to_str()) == Some("json") {
            if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                usernames.push(stem.to_string());
            }
        }
    }

    Ok(usernames)
}

/// Get path to user's config file: `users/<username>/config.toml`.
/// The `profile` parameter is ignored — there is one config file per user.
pub fn user_config_file(username: &str, _profile: &str) -> Result<PathBuf> {
    Ok(user_dir(username)?.join("config.toml"))
}

/// Get path to user's config file — same as `user_config_file(username, "")`.
pub fn profile_path(username: &str) -> PathBuf {
    user_config_file(username, "").unwrap_or_else(|_| PathBuf::from("config.toml"))
}

/// Get the data directory for a user — alias for `user_vfs_dir`.
pub fn user_vfs_storage(username: &str) -> Result<PathBuf> {
    user_vfs_dir(username)
}

/// Get default VFS storage path for a user (`{base}/users/{username}/data`)
pub fn default_vfs_storage_path(username: &str, _profile: Option<&str>) -> Result<String> {
    let vfs_dir = user_vfs_storage(username)?;
    // VFS directory IS the filesystem - no subdirectory needed
    // Profile is ignored - each user has one VFS namespace
    Ok(vfs_dir.display().to_string())
}

/// Get the runtime directory for IPC sockets.
///
/// Resolves through a three-tier fallback.  Each tier guarantees that sockets
/// live in a directory only the owner can access, preventing socket squatting
/// (see `docs/decisions.md` — *IPC socket placement*).
///
/// | Tier | Condition | Path |
/// |------|-----------|------|
/// | 1 | Linux + `$XDG_RUNTIME_DIR` set (systemd-logind) | `$XDG_RUNTIME_DIR/kotton/` |
/// | 2 | `$TMPDIR` set (macOS per-user temp) | `$TMPDIR/kotton/` |
/// | 3 | Universal fallback | `$KOTTON_BASE_DIR/run/` |
///
/// Tier 3 is always available. It sits under `base_dir`, which is `0o700` when a
/// Kotton component made it — every writer that can make a node's base dir
/// makes it through `fs::create_dir_all_owner_only`, and the socket bind with
/// its own `0o700` `DirBuilder` — and a vault refuses to
/// start in one that is not; a device base dir that already existed keeps
/// whatever mode it was given. `run/`, and any base dir above it, made by the
/// bind is made `0o700` there (`kotton_ipc::OsListener::bind`).
#[cfg(unix)]
pub fn runtime_dir() -> Result<PathBuf> {
    runtime_dir_in(&process_env)
}

/// [`runtime_dir`], resolved in `env` rather than this process's environment.
#[cfg(unix)]
pub fn runtime_dir_in(env: Env) -> Result<PathBuf> {
    // Tier 1: $XDG_RUNTIME_DIR — kernel-backed tmpfs, managed by systemd-logind.
    // Present on Linux with a desktop or server login session; absent in CI and
    // containers.
    #[cfg(target_os = "linux")]
    if let Some(xdg) = env("XDG_RUNTIME_DIR") {
        return Ok(PathBuf::from(xdg).join("kotton"));
    }

    // Tier 2: $TMPDIR — per-user on macOS (e.g. /var/folders/…/T/), giving the
    // same squatting protection without requiring a login manager.
    if let Some(tmpdir) = env("TMPDIR") {
        return Ok(PathBuf::from(tmpdir).join("kotton"));
    }

    // Tier 3: base_dir/run — always works. Under base_dir, which is 0o700 when a
    // Kotton component made it (`fs::create_dir_all_owner_only`); a `run/` the
    // bind makes, it makes 0o700.
    // Used in CI, containers, and WSL2 without systemd.
    Ok(base_dir_in(env)?.join("run"))
}

/// Get the socket path for a named daemon.
///
/// On Unix: `{runtime_dir()}/{name}.sock`
///
/// The parent directory is created with `0o700` by [`kotton_ipc::OsListener::bind`]
/// at daemon startup.  Call-sites must not construct socket paths inline —
/// use this function so the path stays consistent with `runtime_dir`.
///
/// Override the data root with `KOTTON_BASE_DIR` to move both the data
/// directory and the socket together (dev isolation, CI).
#[cfg(unix)]
pub fn daemon_socket_path(name: &str) -> Result<PathBuf> {
    daemon_socket_path_in(&process_env, name)
}

/// [`daemon_socket_path`], resolved in `env` rather than this process's environment:
/// the door a daemon started with `env` will bind, fallback and all.
///
/// For a caller that starts the daemon and then looks for its door. Joining
/// `$XDG_RUNTIME_DIR/kotton/<name>.sock` by hand is right until the path does not fit
/// `sun_path`, and then it names a door nobody opened — a release test in a checkout
/// at a long path looked there and failed
/// (`TASK-release-server-test-looks-for-the-vaults-door-where-a-long-checkout-path-does-not-put-it`).
#[cfg(unix)]
pub fn daemon_socket_path_in(env: Env, name: &str) -> Result<PathBuf> {
    // A *name*, not a path. `Path::join` silently replaces when handed an
    // absolute argument, so passing a resolved socket path here used to yield a
    // different, plausible-looking, unbound path instead of an error — which is
    // how kuid ended up connecting to `…/kuserd.sock.sock` and crash-looping.
    // Names arrive from argv and the environment, so refuse the shape here, once,
    // rather than at each of the six call sites.
    if name.is_empty() || name.contains('/') || name.contains('\0') {
        return Err(anyhow!(
            "daemon socket name {name:?} is not a bare name; \
             pass `kuserd`, not a path — the path is what this function returns"
        ));
    }
    let preferred = runtime_dir_in(env)?.join(format!("{}.sock", name));
    if socket_path_fits(&preferred) {
        return Ok(preferred);
    }
    // The per-user runtime dir overflows `sockaddr_un.sun_path`. This is the macOS
    // case: `$TMPDIR` is a long `/var/folders/<hash>/T/` path, so the full socket
    // path exceeds 104 bytes and `bind()` fails (this broke `xtask` onboarding).
    // Fall back to a short, per-user `/tmp` dir keyed by a stable hash of the
    // preferred path — so `KOTTON_BASE_DIR` dev isolation still maps to distinct
    // sockets, and daemon + client + tooling all derive the *same* path. The
    // squatting protection is unchanged: `OsListener::bind` creates the parent
    // `0o700`, so a pre-squatted dir in world-writable `/tmp` fails the bind.
    let key = short_path_key(&preferred);
    Ok(PathBuf::from(FALLBACK_PARENT)
        .join(format!("{FALLBACK_PREFIX}{key}"))
        .join(format!("{}.sock", name)))
}

/// Where [`daemon_socket_path_in`]'s `sun_path` fallback puts its directories, and
/// what it names them before the key. Both halves of the rule read these, so the
/// composer and [`daemon_socket_fallback_dir`] cannot drift apart.
#[cfg(unix)]
const FALLBACK_PARENT: &str = "/tmp";
#[cfg(unix)]
const FALLBACK_PREFIX: &str = "kotton-";

/// The `/tmp/kotton-<key>/` directory holding `door`, when `door` is one
/// [`daemon_socket_path_in`] fell back to; `None` for a door where the runtime
/// directory put it.
///
/// For a caller that started a daemon and must clean up after it. The daemon makes
/// that directory at bind and leaves it — a daemon's door outliving it is right on
/// a host, where the next start binds there again — but a test's scratch host is gone at the
/// end of the test and the directory outside it is not. Before 2026-09-28 the suite
/// harness and `kvaultd`'s installed-vault test each worked this out for themselves
/// (the second not at all: every run left one behind), and neither copy was the rule
/// (`TASK-the-deep-box-vault-test-leaves-its-short-door-in-tmp`).
#[cfg(unix)]
pub fn daemon_socket_fallback_dir(door: &std::path::Path) -> Option<&std::path::Path> {
    let dir = door.parent()?;
    let key = dir.file_name()?.to_str()?.strip_prefix(FALLBACK_PREFIX)?;
    let ours = dir.parent() == Some(std::path::Path::new(FALLBACK_PARENT))
        && key.len() == 8
        && key.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase());
    ours.then_some(dir)
}

/// `true` if `path` fits in `sockaddr_un.sun_path` on every supported Unix.
///
/// The field is 104 bytes on macOS/BSD and 108 on Linux; use the smaller bound
/// (less one for the NUL terminator) so a path that fits here binds everywhere.
///
/// Public so there is one answer to "does this door fit": the integration suite's
/// harness asks it before placing a test daemon's socket under a `TMPDIR` it does
/// not control, rather than keeping a second copy of the bound
/// (`TASK-a-suite-daemon-placed-isolated-cannot-bind-under-a-long-tmpdir`).
#[cfg(unix)]
pub fn socket_path_fits(path: &std::path::Path) -> bool {
    use std::os::unix::ffi::OsStrExt;
    const SUN_PATH_MAX: usize = 104;
    // Strictly less: the terminating NUL takes the last byte.
    path.as_os_str().as_bytes().len() < SUN_PATH_MAX
}

/// Short, stable, non-cryptographic key derived from a path (FNV-1a → 8 hex).
///
/// Only needs to separate per-user / per-`KOTTON_BASE_DIR` sockets so distinct
/// daemons don't collide in `/tmp`; the `0o700` bind is the security boundary,
/// not this name. Deterministic so every process resolves the same socket.
#[cfg(unix)]
fn short_path_key(path: &std::path::Path) -> String {
    use std::os::unix::ffi::OsStrExt;
    let mut hash: u32 = 0x811c_9dc5; // FNV-1a 32-bit offset basis
    for &b in path.as_os_str().as_bytes() {
        hash ^= b as u32;
        hash = hash.wrapping_mul(0x0100_0193); // FNV-1a prime
    }
    format!("{hash:08x}")
}

/// The IPC socket name used by the **device daemon** (`kdeviced`).
///
/// Defaults to `kdeviced`. Set `KDEVICED_IPC_NAME` to run a dev `kdeviced`
/// instance alongside a production one without name collisions:
///
/// ```sh
/// KDEVICED_IPC_NAME=kdeviced-dev cargo run --bin kdeviced
/// ```
pub fn kdeviced_ipc_name() -> String {
    kdeviced_ipc_name_in(&process_env)
}

/// [`kdeviced_ipc_name`], resolved in `env` rather than this process's environment:
/// the name a `kdeviced` started with `env` answers at.
pub fn kdeviced_ipc_name_in(env: Env) -> String {
    env("KDEVICED_IPC_NAME").unwrap_or_else(|| "kdeviced".to_string())
}

/// Where this machine's `kdeviced` answers, on Unix: [`kdeviced_ipc_name`]'s name
/// through [`daemon_socket_path`]'s rule, composed here and nowhere else.
///
/// The daemon binding it, `kuserd` reaching its supervisor, and `kctl` all ask this.
/// Three sites wrote the two calls out until 2026-09-28, agreeing by copying — the
/// shape [`kuserd_door`] was in before it
/// (`TASK-kdeviceds-door-is-composed-from-its-name-at-three-sites`).
#[cfg(unix)]
pub fn kdeviced_door() -> Result<PathBuf> {
    kdeviced_door_in(&process_env)
}

/// [`kdeviced_door`], resolved in `env` rather than this process's environment: the
/// door a `kdeviced` started with `env` binds. No harness starts a `kdeviced` process
/// with an environment of its own yet — the suite runs one in-process at a door it
/// picks — so this is here for the one that will, and so that [`kdeviced_door`] is
/// the name rule and the path rule composed over one environment, not two reads.
#[cfg(unix)]
pub fn kdeviced_door_in(env: Env) -> Result<PathBuf> {
    daemon_socket_path_in(env, &kdeviced_ipc_name_in(env))
}

/// The IPC socket name used by **`kuserd` in direct dev-launch mode**.
///
/// Defaults to `kuserd`. Only applies when `KOTTON_USER_DID` is not set
/// (i.e. `kuserd` was not spawned by `kdeviced`). In normal operation `kuserd`
/// derives its socket name from the user DID instead.
///
/// Set `KUSERD_IPC_NAME` to target a dev `kuserd` instance from the CLI:
///
/// ```sh
/// KUSERD_IPC_NAME=kuserd-dev cargo run --bin kuserd
/// ```
pub fn kuserd_ipc_name() -> String {
    kuserd_ipc_name_in(&process_env)
}

/// [`kuserd_ipc_name`], resolved in `env` rather than this process's environment:
/// the name a `kuserd` started with `env` in direct-launch mode answers at, so a
/// harness that starts one asks [`daemon_socket_path_in`] for its door by the name
/// the daemon chose, not by a copy of the default.
pub fn kuserd_ipc_name_in(env: Env) -> String {
    env("KUSERD_IPC_NAME").unwrap_or_else(|| "kuserd".to_string())
}

/// Where `kuserd` answers in direct-launch mode, on Unix: [`kuserd_ipc_name`]'s name
/// through [`daemon_socket_path`]'s rule, composed here and nowhere else.
///
/// Every caller that reaches the daemon — the client, the sidecars' fallback, the
/// daemon binding it, the harnesses waiting on it — asks this rather than writing the
/// two calls out. Six sites wrote them out until 2026-09-28, agreeing by copying;
/// a change to how the name and the path combine is now one change
/// (`TASK-the-door-is-composed-from-a-name-at-seven-call-sites`). A `kuserd`
/// spawned by `kdeviced` answers at a per-user door named from its DID instead, and
/// that is not this door.
#[cfg(unix)]
pub fn kuserd_door() -> Result<PathBuf> {
    kuserd_door_in(&process_env)
}

/// [`kuserd_door`], resolved in `env` rather than this process's environment: the
/// door a `kuserd` started with `env` binds, for a harness that starts one and then
/// waits for it.
#[cfg(unix)]
pub fn kuserd_door_in(env: Env) -> Result<PathBuf> {
    daemon_socket_path_in(env, &kuserd_ipc_name_in(env))
}

/// The Windows pipe path a pipe *name* opens at: `\\.\pipe\<name>`, composed here
/// and nowhere else.
///
/// `IpcEndpoint::NamedPipe` carries the name; the transport opening it, `xtask`'s
/// readiness probe, and `kotton config paths` printing it all ask this. Thirteen
/// sites wrote the prefix out until 2026-09-28, and seven of them — all tests —
/// wrote the whole path *into* a `NamedPipe`, where the transport prefixed it a
/// second time; they hand it a name now
/// (`TASK-the-windows-pipe-path-is-composed-by-hand-at-nineteen-sites`).
///
/// It lives beside the doors rather than in `kotton-ipc` beside the transport,
/// because it is the Windows half of the same question they answer — where does a
/// daemon with this name answer — and two of its three askers (`xtask`, which does
/// not depend on the transport, and the CLI printing a path for a person) are not
/// opening anything. The transport opens what this composes, as on Unix it binds
/// what [`daemon_socket_path`] composes.
///
/// A pure string function on every platform, so its test runs where the tree is
/// built: nothing here is compiled for Windows in the loop's containers.
pub fn pipe_path(name: &str) -> String {
    format!(r"\\.\pipe\{name}")
}

/// Where a sidecar finds the `kuserd` that spawned it, on Unix.
///
/// Two variables, two shapes, one for each. `KUSERD_IPC_SOCKET` is the socket
/// *path* the supervisor bound, used exactly as given and never joined;
/// `KUSERD_IPC_NAME` is a bare *name*, resolved through [`daemon_socket_path`],
/// which refuses a path. Until 2026-09-15 the supervisor put the path in the
/// name variable: `khttpd` read it as a path and worked, `ksyncd` and `kquicd`
/// resolved it as a name and were refused on every start, and the supervisor
/// restarted them forever (`TASK-ksyncd-cannot-start-on-unix-and-the-supervisor-hides-it`).
/// The path variable exists so the guard in [`daemon_socket_path`] never has to
/// be bypassed: a supervisor that knows the path says so in a variable that
/// means *path*.
#[cfg(unix)]
pub fn kuserd_socket_from_env() -> Result<PathBuf> {
    match std::env::var("KUSERD_IPC_SOCKET") {
        Ok(p) if !p.trim().is_empty() => Ok(PathBuf::from(p.trim())),
        _ => kuserd_door(),
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    /// A resolved path handed back in as a name must be refused, not silently
    /// turned into a different path.
    ///
    /// `Path::join` replaces on an absolute argument, so before this guard
    /// `daemon_socket_path("/run/kuserd.sock")` returned `/run/kuserd.sock.sock`
    /// — a path that binds nothing and reads as plausible in a log line. kuid
    /// crash-looped on it. Names reach this function from argv and the
    /// environment, so the shape is checked once, here.
    #[cfg(unix)]
    #[test]
    fn a_path_is_not_a_daemon_name() {
        for bad in ["/root/.local/share/kotton/run/kuserd.sock", "run/kuserd", ""] {
            assert!(
                daemon_socket_path(bad).is_err(),
                "daemon_socket_path accepted {bad:?}, which is not a bare name"
            );
        }
        assert!(daemon_socket_path("kuserd").is_ok());
        assert!(daemon_socket_path("kuserd-a1b2c3d4").is_ok());
    }

    #[test]
    fn test_path_structure() {
        let username = "alice";

        // Test that all paths are consistent
        let user_root = user_dir(username).unwrap();
        assert!(user_root.to_string_lossy().contains("alice"));

        let identity = user_identity_file(username).unwrap();
        assert!(identity.to_string_lossy().contains(".kotton"));
        assert!(identity.to_string_lossy().ends_with("identity.json"));
    }

    #[cfg(unix)]
    #[test]
    fn short_socket_path_fits() {
        assert!(socket_path_fits(std::path::Path::new(
            "/tmp/kotton/kuserd.sock"
        )));
    }

    #[cfg(unix)]
    #[test]
    fn long_macos_tmpdir_socket_overflows_then_short_fallback_fits() {
        // Mimic a macOS $TMPDIR=/var/folders/<hash>/T/ runtime dir long enough to
        // overflow sun_path (104). The raw path must be rejected…
        let long_tmpdir = format!("/var/folders/{}/T/kotton", "ab".repeat(50));
        let overflowing = std::path::Path::new(&long_tmpdir).join("kuserd.sock");
        assert!(
            !socket_path_fits(&overflowing),
            "expected overflow for {} ({} bytes)",
            overflowing.display(),
            overflowing.as_os_str().len()
        );

        // …and the /tmp fallback this drives must fit on every Unix.
        let key = short_path_key(&overflowing);
        let fallback = std::path::PathBuf::from("/tmp")
            .join(format!("kotton-{key}"))
            .join("kuserd.sock");
        assert!(
            socket_path_fits(&fallback),
            "fallback must fit: {}",
            fallback.display()
        );
        // Key is deterministic.
        assert_eq!(key, short_path_key(&overflowing));
    }

    /// A daemon started with an environment of its own has its door found by the same
    /// rule, fallback included: a runtime directory short enough gets
    /// `$XDG_RUNTIME_DIR/kotton/<name>.sock`, and one too long for `sun_path` gets the
    /// short `/tmp` path, never the joined one.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_door_is_found_in_the_environment_the_daemon_was_given() {
        let short = |k: &str| (k == "XDG_RUNTIME_DIR").then(|| "/run/kotton-vault".to_string());
        assert_eq!(
            daemon_socket_path_in(&short, "vault").unwrap(),
            PathBuf::from("/run/kotton-vault/kotton/vault.sock")
        );

        // Only the length matters: a runtime dir deep enough that the joined door
        // passes `socket_path_fits`'s bound and the composer falls back.
        let long_run = format!("/{}/run/kotton-vault", "d".repeat(100));
        let long = |k: &str| (k == "XDG_RUNTIME_DIR").then(|| long_run.clone());
        let joined = PathBuf::from(&long_run).join("kotton").join("vault.sock");
        assert!(!socket_path_fits(&joined), "{} should not fit", joined.display());
        let door = daemon_socket_path_in(&long, "vault").unwrap();
        assert_ne!(door, joined);
        assert!(socket_path_fits(&door), "{} does not fit", door.display());
        assert!(door.starts_with("/tmp") && door.ends_with("vault.sock"), "{}", door.display());

        // Nothing in the environment but a base directory: tier 3.
        let base = |k: &str| (k == "KOTTON_BASE_DIR").then(|| "/b".to_string());
        assert_eq!(daemon_socket_path_in(&base, "vault").unwrap(), PathBuf::from("/b/run/vault.sock"));
        // And a path is refused as a name here too.
        assert!(daemon_socket_path_in(&short, "/run/vault.sock").is_err());
    }

    /// A door the fallback made names its own directory, the one `/tmp/kotton-<key>/`
    /// holding it, and no other door names one: not a door where the runtime directory
    /// put it, and not a directory that only looks like the fallback's
    /// (`TASK-the-deep-box-vault-test-leaves-its-short-door-in-tmp`).
    #[cfg(target_os = "linux")]
    #[test]
    fn a_door_the_fallback_made_names_the_directory_it_made() {
        // Only the length matters: a runtime dir deep enough that the joined door
        // passes `socket_path_fits`'s bound and the composer falls back.
        let long_run = format!("/{}/run/kotton-vault", "d".repeat(100));
        let long = |k: &str| (k == "XDG_RUNTIME_DIR").then(|| long_run.clone());
        let door = daemon_socket_path_in(&long, "vault").unwrap();
        let dir = daemon_socket_fallback_dir(&door).expect("a fallback door names its directory");
        assert_eq!(Some(dir), door.parent());
        assert!(dir.starts_with("/tmp") && dir != std::path::Path::new("/tmp"), "{}", dir.display());

        let short = |k: &str| (k == "XDG_RUNTIME_DIR").then(|| "/run/kotton-vault".to_string());
        assert_eq!(daemon_socket_fallback_dir(&daemon_socket_path_in(&short, "vault").unwrap()), None);
        for not_ours in [
            "/tmp/vault.sock",
            "/tmp/kotton-test-abc123/daemon.sock",
            "/tmp/kotton-CD7FC414/vault.sock",
            "/var/tmp/kotton-cd7fc414/vault.sock",
            "/tmp/x/kotton-cd7fc414/vault.sock",
        ] {
            assert_eq!(daemon_socket_fallback_dir(std::path::Path::new(not_ours)), None, "{not_ours}");
        }
    }

    /// The name a direct-launch `kuserd` answers at is read from the environment it
    /// was given, not this process's: `KUSERD_IPC_NAME` when that sets it, else
    /// `kuserd`.
    #[test]
    fn kuserds_name_is_read_from_the_environment_it_was_given() {
        let none = |_: &str| None;
        assert_eq!(kuserd_ipc_name_in(&none), "kuserd");
        let named = |k: &str| (k == "KUSERD_IPC_NAME").then(|| "kuserd-dev".to_string());
        assert_eq!(kuserd_ipc_name_in(&named), "kuserd-dev");
    }

    /// `kuserd`'s door is one rule with two ways in: over this process's environment
    /// and over a given one. Given this process's environment, the `_in` form names
    /// the door the plain form does, and over any environment it is the name rule and
    /// the path rule composed, not something beside them.
    #[cfg(unix)]
    #[test]
    fn kuserds_door_is_the_same_door_in_either_form() {
        let this_process = |k: &str| std::env::var(k).ok();
        assert_eq!(kuserd_door().unwrap(), kuserd_door_in(&this_process).unwrap());
        assert_eq!(
            kuserd_door().unwrap(),
            daemon_socket_path(&kuserd_ipc_name()).unwrap()
        );

        let given = |k: &str| match k {
            "KOTTON_BASE_DIR" => Some("/b".to_string()),
            "KUSERD_IPC_NAME" => Some("kuserd-dev".to_string()),
            _ => None,
        };
        assert_eq!(kuserd_door_in(&given).unwrap(), PathBuf::from("/b/run/kuserd-dev.sock"));
        assert_eq!(
            kuserd_door_in(&given).unwrap(),
            daemon_socket_path_in(&given, &kuserd_ipc_name_in(&given)).unwrap()
        );
    }

    /// `kdeviced`'s door is one rule with two ways in, as `kuserd`'s is: given this
    /// process's environment the `_in` form names the door the plain form does, that
    /// door is the composition the three sites wrote out before, and over any
    /// environment it is the name rule and the path rule composed over that one.
    #[cfg(unix)]
    #[test]
    fn kdeviceds_door_is_the_same_door_in_either_form() {
        let this_process = |k: &str| std::env::var(k).ok();
        assert_eq!(kdeviced_door().unwrap(), kdeviced_door_in(&this_process).unwrap());
        assert_eq!(
            kdeviced_door().unwrap(),
            daemon_socket_path(&kdeviced_ipc_name()).unwrap()
        );

        let none = |_: &str| None;
        assert_eq!(kdeviced_ipc_name_in(&none), "kdeviced");
        let given = |k: &str| match k {
            "KOTTON_BASE_DIR" => Some("/b".to_string()),
            "KDEVICED_IPC_NAME" => Some("kdeviced-dev".to_string()),
            _ => None,
        };
        assert_eq!(kdeviced_door_in(&given).unwrap(), PathBuf::from("/b/run/kdeviced-dev.sock"));
        assert_eq!(
            kdeviced_door_in(&given).unwrap(),
            daemon_socket_path_in(&given, &kdeviced_ipc_name_in(&given)).unwrap()
        );
    }

    /// **Nobody works out a daemon's door by hand but the daemons that own one.** A
    /// scan of the tree, the way `windows-check` reads it, with three needles, each
    /// with an allow list that says why each file on it is there:
    ///
    /// - **The path rule, called.** Any code line calling `daemon_socket_path(` or
    ///   `daemon_socket_path_in(`, with any argument — so a wrapper handed a name
    ///   (`kctl`'s `endpoint_for`) is counted, not only a call spelled `(&kuserd_ipc_name())`.
    /// - **The runtime-dir rule, copied.** Any file outside `core/common` that reads
    ///   `XDG_RUNTIME_DIR` or `TMPDIR` and joins a `.sock` in the same file: the tiers of
    ///   [`runtime_dir_in`] written out, which also leaves out the `sun_path` fallback.
    ///   The needle is the variable's name, so a join through `std::env::temp_dir()`,
    ///   which reads `TMPDIR` without spelling it, is not seen here; that join is
    ///   [`a_socket_joined_onto_the_temp_dir_asks_whether_it_fits`]'s.
    /// - **The name rule, composed.** Any file but this one calling `kuserd_ipc_name_in`
    ///   or `kdeviced_ipc_name_in`, the harnesses' spelling of the pairs
    ///   [`kuserd_door_in`] and [`kdeviced_door_in`] compose — or calling
    ///   `kuserd_ipc_name` or `kdeviced_ipc_name` in a file with a `.sock"` literal,
    ///   the same composition over this process's environment with the path rule left
    ///   out altogether (`ConfigCommand::Paths` printed `/tmp/<name>.sock` that way
    ///   until 2026-09-28).
    ///
    /// A new copy of any daemon's door is refused here rather than noticed in review
    /// (`TASK-the-door-is-composed-from-a-name-at-seven-call-sites`,
    /// `TASK-a-suite-test-and-xtasks-poller-still-derive-kuserds-door-by-a-copy-of-the-rule`,
    /// `TASK-kdeviceds-door-is-composed-from-its-name-at-three-sites`).
    ///
    /// It reads lines, and it skips lines that open with `//`. It cannot see a call split
    /// across two lines, one made through an alias, a `.sock` literal built from pieces
    /// with no `.sock"` in it, a name read in one file and joined onto `.sock` in another
    /// (the process-name needle is a same-file conjunction), or a copy in a language that
    /// is not Rust
    /// (`infra/release/clean-machine.sh` asks `kotton config paths` for its door since
    /// 2026-09-28 rather than joining tier 3 in shell).
    #[test]
    fn only_the_daemons_that_own_a_door_compose_one_from_a_name() {
        const PATH_RULE: &[(&str, &str)] = &[
            ("client/cli/src/kctl.rs", "`endpoint_for` is handed the per-user name `start_user` returns; `kdeviced`'s door is `kdeviced_door`"),
            ("core/common/src/paths.rs", "the rule itself"),
            ("core/kuserd/src/main.rs", "the per-user door `kdeviced` names from a DID; the direct-launch door is `kuserd_door`"),
            ("core/kvaultd/src/instance.rs", "a test serves a vault at the tier-3 door `daemon_socket_path_in` resolves for an env naming only `KOTTON_BASE_DIR`, as a hand-started vault gets it"),
            ("core/kvaultd/src/main.rs", "`kvaultd` binds its own door"),
            ("core/kvaultd/tests/a_verb_finds_the_installed_vault.rs", "the vault's door, over the environment its scratch host starts it with"),
            ("tests/tests/suite/headless.rs", "the vault's door, over the `XDG_RUNTIME_DIR` its host starts the installed unit with and the name its installed `vault.env` gives; the vault prints no door to read it from"),
            ("xtask/src/release_server.rs", "the vault's door, over the env file the release test starts it with"),
        ];
        const RUNTIME_RULE: &[(&str, &str)] = &[
            ("core/kvaultd/tests/a_verb_finds_the_installed_vault.rs", "sets `XDG_RUNTIME_DIR` for the scratch host it installs, and joins the tier by hand only to assert the door is not that path"),
            ("xtask/src/release_server.rs", "sets `XDG_RUNTIME_DIR` for the scratch host it installs, and joins the tier by hand only to assert the door is not that path"),
        ];
        let (root, files) = rust_files();

        // Code lines only, and a needle that is a whole identifier: `user_daemon_socket_path(`
        // is a different function.
        let code = |src: &str| -> Vec<String> {
            src.lines().filter(|l| !l.trim_start().starts_with("//")).map(str::to_string).collect()
        };
        let calls = |lines: &[String], f: &str| {
            lines.iter().any(|l| {
                l.match_indices(f).any(|(i, _)| {
                    !l[..i].chars().next_back().is_some_and(|c| c.is_alphanumeric() || c == '_')
                })
            })
        };
        let mut path_rule = Vec::new();
        let mut runtime_rule = Vec::new();
        let mut name_rule = Vec::new();
        for f in &files {
            let lines = code(&std::fs::read_to_string(f).unwrap());
            let rel = f.strip_prefix(&root).unwrap().to_string_lossy().replace('\\', "/");
            if calls(&lines, "daemon_socket_path(") || calls(&lines, "daemon_socket_path_in(") {
                path_rule.push(rel.clone());
            }
            if !rel.starts_with("core/common/")
                && lines.iter().any(|l| l.contains("XDG_RUNTIME_DIR") || l.contains("TMPDIR"))
                && lines.iter().any(|l| l.contains(".sock"))
            {
                runtime_rule.push(rel.clone());
            }
            // The process-env name beside a `.sock` literal is the same composition
            // with no `_in`: `config paths` printed `format!("/tmp/{name}.sock")`
            // over `kuserd_ipc_name()` until 2026-09-28, and neither needle above
            // saw it (`TASK-config-paths-prints-a-socket-nothing-binds`). A Windows
            // arm that names a pipe from the same call writes no `.sock`.
            let by_process_name = (calls(&lines, "kuserd_ipc_name(") || calls(&lines, "kdeviced_ipc_name("))
                && lines.iter().any(|l| l.contains(".sock\""));
            if rel != "core/common/src/paths.rs"
                && (calls(&lines, "kuserd_ipc_name_in(") || calls(&lines, "kdeviced_ipc_name_in(") || by_process_name)
            {
                name_rule.push(rel);
            }
        }
        path_rule.sort();
        runtime_rule.sort();
        let names = |allowed: &[(&str, &str)]| allowed.iter().map(|(f, _)| f.to_string()).collect::<Vec<_>>();
        assert_eq!(
            path_rule,
            names(PATH_RULE),
            "a door composed from a name outside the files allowed to; `kuserd`'s is `kuserd_door`/`kuserd_door_in`, `kdeviced`'s is `kdeviced_door`/`kdeviced_door_in`"
        );
        assert_eq!(
            runtime_rule,
            names(RUNTIME_RULE),
            "the runtime-dir rule written out by hand; ask `kotton_common::paths` for the door"
        );
        assert!(
            name_rule.is_empty(),
            "a daemon's door composed by hand in {name_rule:?}; call `kuserd_door`/`kuserd_door_in` or `kdeviced_door`/`kdeviced_door_in`"
        );
    }

    /// **A socket joined onto the system temp directory asks whether it fits.** The
    /// sibling of [`only_the_daemons_that_own_a_door_compose_one_from_a_name`] for the
    /// door that scan's runtime-dir needle cannot see: that needle is the *variable's
    /// name*, `TMPDIR` beside `.sock`, and a join through `std::env::temp_dir()` reads
    /// `TMPDIR` without ever spelling it. Sixteen such joins were fixed by hand on
    /// 2026-09-28 — six unit tests in `core/` and ten suite sites — and the scan saw none
    /// of them (`TASK-three-unit-tests-join-their-socket-onto-tmpdir-by-hand`,
    /// `TASK-suite-tests-that-join-their-own-socket-path-cannot-bind-under-a-long-tmpdir`).
    /// Under a `TMPDIR` long enough, each failed its bind on `SUN_LEN`.
    ///
    /// It is its own test rather than a fourth needle there because it is a different
    /// rule: that scan refuses a copy of a daemon's door, which someone else must derive
    /// identically, and a test's socket is derived by nobody. What this one refuses is a
    /// socket placed under a directory whose length nobody here chose.
    ///
    /// **The needle.** On code lines only, and outside `core/common/`: a file that calls
    /// `temp_dir()` or `tempdir()` as a whole identifier — `std::env::temp_dir()`,
    /// `env::temp_dir()`, `tempfile::tempdir()`, and a `tempdir()` imported bare; not
    /// `tempdir_in(`, whose caller names the directory — and names `.sock"` or
    /// `UnixSocket(`. Each file on the allow list says why it is there: it asks
    /// [`socket_path_fits`] (directly, or through a door rule that does), or its temp
    /// directory is not where its socket goes.
    ///
    /// **It is a same-file conjunction, and that is its blind spot.** A file is refused
    /// when both halves are in it, not when one is joined onto the other, so it cannot
    /// see a temp directory made in one file and handed to a socket join in another — a
    /// helper returning `temp_dir()` and a caller writing `.join("x.sock")`. The door
    /// scan's process-name needle has the same shape and names the same gap. The other
    /// side of the same granularity is the allow list: a listed file may add a second,
    /// unchecked join beside the one its reason is about, and nothing here tells them
    /// apart. A same-line needle was measured instead and would miss every suite copy the
    /// suite record fixed, which split the join across two lines; the file-level needle
    /// with reasons is the smaller loss. It also cannot see `TempDir::new()`, a socket
    /// path spelled with no `.sock"` handed to something other than `UnixSocket(` (a raw
    /// `UnixListener::bind`), a call split across lines, or a join in a language that is
    /// not Rust. It errs the other way too: a `temp_dir()` in a trailing `//` comment or
    /// inside a string literal on a code line *is* counted, so a false hit refuses rather
    /// than passes, and the remedy is an allow-list entry with its reason.
    ///
    /// The allow list is not the fix. A file on it for a socket's sake is a file whose
    /// socket *could* be placed by hand; what makes it safe is the `socket_path_fits` its
    /// reason names, and the suite has one function (`door_in`) so that there is nothing
    /// left to copy.
    #[test]
    fn a_socket_joined_onto_the_temp_dir_asks_whether_it_fits() {
        const ALLOWED: &[(&str, &str)] = &[
            ("core/kuserd/src/agent/co_member_tests.rs", "`alice_unlocked` hands a daemon `kuserd.sock` under its tempdir base and never calls `run`, the one place the daemon listens: nothing binds the path"),
            ("core/kuserd/src/agent/handlers/device_config.rs", "`construct` hands a daemon `kuserd.sock` under its tempdir base and never serves it: nothing in the file listens, so nothing binds the path"),
            ("core/kuserd/src/agent/message_open_tests.rs", "`alice_unlocked` hands a daemon `kuserd.sock` under its tempdir base and never calls `run`, the one place the daemon listens: nothing binds the path"),
            ("core/kuserd/src/agent/mod.rs", "its `UnixSocket(` are match arms reading an endpoint it was handed; its tempdirs are binary-lookup directories no socket goes in"),
            ("core/kuserd/src/agent/revoke_device_tests.rs", "`alice_at` hands a daemon `kuserd.sock` under its tempdir base and never calls `run`, the one place the daemon listens: nothing binds the path"),
            ("core/kuserd/src/agent/set_lock_policy_tests.rs", "`alice_booted` hands a daemon `kuserd.sock` under its tempdir base and never calls `run`, the one place the daemon listens: nothing binds the path"),
            ("core/kuserd/src/agent/streamed.rs", "its socket tests bind in a `tempfile::tempdir_in(\"/tmp\")` they own on Unix; the `tempdir()` is Windows-only, a daemon base whose door is a named pipe, so no socket joins it"),
            ("core/kuserd/src/agent/unlock_tests.rs", "`booted` hands a daemon `kuserd.sock` under its tempdir base and never calls `run`, the one place the daemon listens: nothing binds the path"),
            ("core/kvaultd/src/instance.rs", "its vault tests' door is `control::tests::a_door`, a `tempdir_in(\"/tmp\")` the test owns, or `daemon_socket_path_in`, which asks `socket_path_fits`; its `tempdir()` is a root no socket joins"),
            ("tests/tests/suite/common/mod.rs", "`unique_ipc` is `door_in(temp_dir(), …)`, and `door_in` asks `socket_path_fits`: the rule's home in the suite"),
            ("tests/tests/suite/kuid_surface.rs", "`boot_a_daemon_at` asks `door_in` for its socket, which asks `socket_path_fits`; its tempdirs are bases"),
            ("tests/tests/suite/two_node_transfer.rs", "the door is `kuserd_door_in` over an env naming the tempdir, which asks `socket_path_fits`"),
            ("xtask/src/release.rs", "the install test's door is `kuserd_door_in`, which asks `socket_path_fits`; the one `.sock\"` join is asserted not to be the door"),
            ("xtask/src/release_server.rs", "the vault's door is `daemon_socket_path_in` over its env file, which asks `socket_path_fits`; the `.sock\"` join is asserted not to be the door"),
        ];
        let (root, files) = rust_files();
        let calls = |l: &str, f: &str| {
            l.match_indices(f).any(|(i, _)| {
                !l[..i].chars().next_back().is_some_and(|c| c.is_alphanumeric() || c == '_')
            })
        };
        let mut found = Vec::new();
        for f in &files {
            let rel = f.strip_prefix(&root).unwrap().to_string_lossy().replace('\\', "/");
            if rel.starts_with("core/common/") {
                continue;
            }
            let src = std::fs::read_to_string(f).unwrap();
            let lines = src.lines().filter(|l| !l.trim_start().starts_with("//")).collect::<Vec<_>>();
            if lines.iter().any(|l| calls(l, "temp_dir()") || calls(l, "tempdir()"))
                && lines.iter().any(|l| l.contains(".sock\"") || l.contains("UnixSocket("))
            {
                found.push(rel);
            }
        }
        found.sort();
        let allowed = ALLOWED.iter().map(|(f, _)| f.to_string()).collect::<Vec<_>>();
        assert_eq!(
            found, allowed,
            "a socket beside the system temp directory, in a file not on the list; ask `socket_path_fits`, or bind in a `tempfile::tempdir_in(\"/tmp\")` the test owns"
        );
    }

    /// Every `.rs` file under the roots the door scans read, the way `windows-check`
    /// reads the tree, and the repository root they are relative to.
    fn rust_files() -> (PathBuf, Vec<PathBuf>) {
        const ROOTS: &[&str] = &["core", "client", "system", "guest", "tools", "infra", "xtask", "tests"];
        fn walk(dir: &std::path::Path, out: &mut Vec<PathBuf>) {
            let Ok(entries) = std::fs::read_dir(dir) else { return };
            for entry in entries.flatten() {
                let path = entry.path();
                let name = entry.file_name();
                if path.is_dir() {
                    if !matches!(name.to_str(), Some("target" | "out" | "node_modules") | None)
                        && !name.to_string_lossy().starts_with('.')
                    {
                        walk(&path, out);
                    }
                } else if path.extension().is_some_and(|e| e == "rs") {
                    out.push(path);
                }
            }
        }
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let mut files = Vec::new();
        for r in ROOTS {
            walk(&root.join(r), &mut files);
        }
        assert!(files.len() > 100, "the scan found {} files; it is not reading the tree", files.len());
        (root, files)
    }

    #[test]
    fn a_pipe_name_opens_under_the_pipe_namespace() {
        assert_eq!(pipe_path("kuserd"), r"\\.\pipe\kuserd");
        assert_eq!(pipe_path("kotton-test-0f"), r"\\.\pipe\kotton-test-0f");
    }

    /// **Nobody writes the Windows pipe prefix but [`pipe_path`].** The sibling of
    /// [`only_the_daemons_that_own_a_door_compose_one_from_a_name`] for the half of the
    /// door that scan cannot see: a pipe path has no `.sock`. Two needles, on code lines
    /// only — the raw spelling `.\pipe\` and the escaped one `.\\pipe\\` that
    /// `config paths` wrote until 2026-09-28
    /// (`TASK-the-windows-pipe-path-is-composed-by-hand-at-nineteen-sites`).
    ///
    /// The allow list starts empty: the merge that added this left no copy, and seven of
    /// the thirteen it removed were tests writing the whole path into a `NamedPipe`, which
    /// carries a *name*. A file that must spell the prefix goes on the list with its
    /// reason, and the list is expected to stay short.
    ///
    /// It reads lines and skips lines that open with `//`, so a doc comment naming the
    /// shape is not a copy. It cannot see the prefix built from pieces, the
    /// `\\?\pipe\` or forward-slash spellings Windows also accepts, or a copy in a
    /// language that is not Rust.
    #[test]
    fn only_pipe_path_writes_the_pipe_prefix() {
        const ALLOWED: &[(&str, &str)] = &[];
        let (root, files) = rust_files();
        let mut found = Vec::new();
        for f in &files {
            let rel = f.strip_prefix(&root).unwrap().to_string_lossy().replace('\\', "/");
            if rel == "core/common/src/paths.rs" {
                continue;
            }
            let src = std::fs::read_to_string(f).unwrap();
            if src
                .lines()
                .filter(|l| !l.trim_start().starts_with("//"))
                .any(|l| l.contains(r".\pipe\") || l.contains(r".\\pipe\\"))
            {
                found.push(rel);
            }
        }
        found.sort();
        let allowed = ALLOWED.iter().map(|(f, _)| f.to_string()).collect::<Vec<_>>();
        assert_eq!(found, allowed, "the Windows pipe prefix written by hand; call `kotton_common::paths::pipe_path`");
    }
}
