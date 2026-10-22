// SPDX-License-Identifier: AGPL-3.0-or-later
//! Spawning a real `khttpd` against a test daemon, the way `kuserd` does it.
//!
//! The gateway is started from the configuration the daemon hands it
//! (`khttpd_spawn_env`), never from values a test made up — that is the property
//! `gateway_bind` exists to hold, and this helper is its spawn code lifted out so
//! the surface test can start the same gateway and point a browser at it.

use super::TestEnv;
#[cfg(unix)]
use kotton_sys::ipc::IpcEndpoint;
use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const READY_TIMEOUT: Duration = Duration::from_secs(30);

/// A running gateway; killed when dropped.
pub struct Gateway {
    child: Child,
}

impl Drop for Gateway {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// A port nothing is listening on right now.
pub fn free_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").expect("reserve a port");
    l.local_addr().expect("reserved port has an address").port()
}

/// Start `khttpd` for `env`'s daemon and wait for it to report the address it
/// bound. The web-shell configuration must already be set on the daemon.
pub async fn spawn(env: &TestEnv) -> (Gateway, String) {
    spawn_as(env, env.gateway_token.clone()).await
}

/// As [`spawn`], authenticating the gateway with `token` — a bootstrap token
/// minted for the user whose shell it serves, the way `kuserd` mints one at
/// spawn. `env.gateway_token` is for `"owner"`; a test whose user is someone
/// else mints its own with `mint_gateway_bootstrap_token`.
pub async fn spawn_as(env: &TestEnv, token: String) -> (Gateway, String) {
    let spawn_env = env.daemon.khttpd_spawn_env().await.expect("khttpd_spawn_env");

    let socket = match &env.endpoint {
        #[cfg(unix)]
        IpcEndpoint::UnixSocket(p) => p.display().to_string(),
        #[allow(unreachable_patterns)]
        other => format!("{other:?}"),
    };
    // A socket is passed as a socket: `KUSERD_IPC_SOCKET` is the path, used as
    // given; `KUSERD_IPC_NAME` is a bare name and the daemon-side resolver
    // refuses a path in it (`kotton_common::kuserd_socket_from_env`). This
    // harness put the path in the name variable until 2026-09-15, which is what
    // the supervisor did too and why `ksyncd` never started on Unix.
    let mut envs: Vec<(String, String)> = vec![
        ("KHTTPD_BOOTSTRAP_TOKEN".into(), token),
        (if cfg!(windows) { "KUSERD_IPC_NAME" } else { "KUSERD_IPC_SOCKET" }.into(), socket),
    ];
    envs.extend(spawn_env.into_iter().map(|(k, v)| (k.to_string(), v)));
    spawn_with(envs).await
}

/// `khttpd enroll` on "another machine": generates its key in `dir`, prints the
/// code a node dials, shows its six digits, and writes the bundle when admitted.
/// Returns the code and a receiver of the lines it prints after it (`sas=…`,
/// `enrolled=…`); the child is killed when the handle drops.
pub async fn spawn_enroll(dir: &std::path::Path) -> (Gateway, String, std::sync::mpsc::Receiver<String>) {
    let mut child = Command::new(super::bins::require(super::bins::Bin::Khttpd))
        .arg("enroll")
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("KHTTPD_GATEWAY_DIR", dir.display().to_string())
        .env("KHTTPD_ENROLL_PORT", free_port().to_string())
        .env("KHTTPD_NAME", "vps-gateway")
        .env("RUST_LOG", "info")
        .env("NO_COLOR", "1")
        .envs(std::env::var("KOTTON_PAIR_LOCAL_ONLY").ok().map(|v| ("KOTTON_PAIR_LOCAL_ONLY", v)))
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn khttpd enroll");
    let stdout = child.stdout.take().expect("piped stdout");
    let (tx, rx) = std::sync::mpsc::channel::<String>();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            if tx.send(line).is_err() {
                return;
            }
        }
    });
    let code = tokio::task::spawn_blocking({
        let deadline = Instant::now() + READY_TIMEOUT;
        move || loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            assert!(!remaining.is_zero(), "khttpd enroll printed no code within {READY_TIMEOUT:?}");
            match rx.recv_timeout(remaining) {
                Ok(line) => {
                    if let Some(code) = line.strip_prefix("code=") {
                        return (code.to_string(), rx);
                    }
                }
                Err(e) => panic!("khttpd enroll ended before printing a code: {e}"),
            }
        }
    })
    .await
    .expect("reader task");
    (Gateway { child }, code.0, code.1)
}

/// A gateway on "another machine" (RFC-0078): started from the directory
/// `khttpd enroll` filled, with no daemon socket and no bootstrap token. It
/// reaches the node only through the relay its bundle names. Serves
/// `static_dir` on a free loopback port.
pub async fn spawn_gateway(dir: &std::path::Path, static_dir: &str) -> (Gateway, String) {
    spawn_with(vec![
        ("KHTTPD_GATEWAY_DIR".into(), dir.display().to_string()),
        ("KHTTPD_PORT".into(), free_port().to_string()),
        ("KHTTPD_BIND".into(), "loopback".into()),
        ("KHTTPD_STATIC_DIR".into(), static_dir.to_string()),
    ])
    .await
}

/// As [`spawn_gateway`], but the way it runs behind a TLS-terminating proxy on
/// its host: plain HTTP on loopback (`KHTTPD_TLS=off`).
pub async fn spawn_gateway_plain(dir: &std::path::Path, static_dir: &str) -> (Gateway, String) {
    spawn_with(vec![
        ("KHTTPD_GATEWAY_DIR".into(), dir.display().to_string()),
        ("KHTTPD_PORT".into(), free_port().to_string()),
        ("KHTTPD_BIND".into(), "loopback".into()),
        ("KHTTPD_STATIC_DIR".into(), static_dir.to_string()),
        ("KHTTPD_TLS".into(), "off".into()),
    ])
    .await
}

async fn spawn_with(envs: Vec<(String, String)>) -> (Gateway, String) {
    let mut child = Command::new(super::bins::require(super::bins::Bin::Khttpd))
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .envs(std::env::var("KOTTON_PAIR_LOCAL_ONLY").ok().map(|v| ("KOTTON_PAIR_LOCAL_ONLY", v)))
        .envs(envs)
        .env("RUST_LOG", "info")
        .env("NO_COLOR", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn khttpd");

    let stdout = child.stdout.take().expect("piped stdout");
    let stderr = child.stderr.take().expect("piped stderr");
    let gateway = Gateway { child };

    let (tx, rx) = std::sync::mpsc::channel();
    for stream in [
        Box::new(stdout) as Box<dyn std::io::Read + Send>,
        Box::new(stderr) as Box<dyn std::io::Read + Send>,
    ] {
        let tx = tx.clone();
        std::thread::spawn(move || {
            for line in BufReader::new(stream).lines().map_while(Result::ok) {
                if tx.send(line).is_err() {
                    return;
                }
            }
        });
    }
    drop(tx);

    let addr = tokio::task::spawn_blocking(move || {
        let deadline = Instant::now() + READY_TIMEOUT;
        let mut seen = Vec::new();
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            assert!(
                !remaining.is_zero(),
                "khttpd never reported a bound address within {READY_TIMEOUT:?}.\noutput:\n{}",
                seen.join("\n"),
            );
            match rx.recv_timeout(remaining) {
                Ok(line) => {
                    if line.contains("gateway listening") {
                        let addr = line
                            .split("local_addr=")
                            .nth(1)
                            .and_then(|rest| rest.split_whitespace().next())
                            .unwrap_or_else(|| panic!("no local_addr in: {line}"))
                            .to_string();
                        // Everything the gateway says after this goes to the
                        // test's stderr, so a gateway that dies mid-test says why.
                        std::thread::spawn(move || {
                            for line in rx.iter() {
                                eprintln!("[khttpd] {line}");
                            }
                        });
                        return addr;
                    }
                    seen.push(line);
                }
                Err(e) => panic!(
                    "khttpd produced no bound address ({e}).\noutput:\n{}",
                    seen.join("\n"),
                ),
            }
        }
    })
    .await
    .expect("reader task");

    (gateway, addr)
}
