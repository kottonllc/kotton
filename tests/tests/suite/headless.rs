// SPDX-License-Identifier: AGPL-3.0-or-later
//! A desktop with no window operates a vault and a relay from the terminal
//! alone (RFC-0084 V23; DEC-0076, which makes a machine with no GPU a terminal
//! and a CLI).
//!
//! `TASK-the-desktop-completes-the-key-it-minted-from-the-line-the-service-prints`,
//! Done-when (5). The person's acts are three, in this order, and nothing else
//! is typed:
//!
//! 1. **mint**, at the desktop's terminal — `mint vault kotton`, `mint relay
//!    kotton` — each printing the command its host runs, with the key's public
//!    half in it and nothing else of the key
//!    (`TASK-mint-prints-the-hosts-install-command-and-is-verb-first`);
//! 2. **request creation** of each instance for its key, with the self-host
//!    adapter: each server archive's `install.sh`, given `KOTTON_OPERATOR_KEY`,
//!    whose last output is the instance's line; then each is started as its
//!    unit would start it;
//! 3. **paste the lines** creation returned, once, in one `enrol` and in
//!    either order — `enrol <the vault's line> <the relay's line>`
//!    (`TASK-enrol-takes-the-lines-an-instance-printed-and-a-vaults-ends-on-an-offer`)
//!    — and say yes to *keep your things here too*.
//!
//! The desktop is a daemon with no window, spoken to through the REPL's own
//! registry, as `kotton` at a terminal speaks to it. It ends with the vault
//! standing at the relay, read from the vault's own door, and keeping this
//! person's things.
//!
//! Unix alone: the self-host adapter is a POSIX shell script, and the vault's door
//! a Unix socket.
#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use kotton::KottonClient;
use kotton_shell::out::Out;
use kotton_shell::{ExitCode, ShellState};
use kotton_sys::ipc::IpcEndpoint;
use kotton_wire::ipc::{OperatedService, UserResponse, VaultRequest};
use kotton_wire::line::InstanceLine;
use tokio::sync::Mutex;

use crate::common::free_port;
use crate::common::relay::relay_bin;

const USER: &str = "lee";

/// Where `just test` left `kvaultd` — `cargo build --bin kvaultd`, into the
/// workspace's own target directory, as `tests/build.rs` asked cargo. `KOTTON_VAULT_BIN`
/// names another binary. Checked with every binary the suite runs (`common::bins`).
fn kvaultd_bin() -> PathBuf {
    crate::common::bins::require(crate::common::bins::Bin::Kvaultd).to_path_buf()
}

/// One host, as the self-host adapter sees it: a root everything is installed
/// under (`KOTTON_ROOT`), a stand-in `id` that says this is an ordinary user,
/// and the archives staged beside it. Under cargo's temporary directory for
/// this crate, not the system's: a vault refuses to be created where its key
/// would not outlive the state (`create_refuses_a_state_whose_key_would_not_outlive_it`).
struct Host {
    dir: PathBuf,
    children: Vec<Child>,
}

impl Drop for Host {
    fn drop(&mut self) {
        for c in &mut self.children {
            let _ = c.kill();
            let _ = c.wait();
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// What each archive holds, as `cargo xtask release-server` packs it.
struct Kind {
    name: &'static str,
    binary: PathBuf,
    unit: &'static str,
    settings: &'static str,
}

impl Host {
    fn new() -> Self {
        let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("headless-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("root/etc/kotton")).unwrap();
        std::fs::create_dir_all(dir.join("shims")).unwrap();
        let id = dir.join("shims/id");
        std::fs::write(&id, "#!/bin/sh\ncase \"$1\" in -u) echo 1000 ;; -un) echo someone ;; *) exit 1 ;; esac\n").unwrap();
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&id, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        Self { dir, children: Vec::new() }
    }

    fn root(&self) -> PathBuf {
        self.dir.join("root")
    }

    /// The archive for `kind`, unpacked under `<dir>/<name>-archive`.
    fn stage(&self, kind: &Kind) -> PathBuf {
        let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let archive = self.dir.join(format!("{}-archive", kind.name));
        std::fs::create_dir_all(archive.join("bin")).unwrap();
        let binary = archive.join("bin").join(kind.binary.file_name().unwrap());
        if std::fs::hard_link(&kind.binary, &binary).is_err() {
            std::fs::copy(&kind.binary, &binary).unwrap();
        }
        std::fs::copy(repo.join("infra/release/install-server.sh"), archive.join("install.sh")).unwrap();
        let unit = Path::new(kind.unit).file_name().unwrap();
        std::fs::copy(repo.join(kind.unit), archive.join(unit)).unwrap();
        let env = Path::new(kind.settings).file_name().unwrap();
        std::fs::copy(repo.join(kind.settings), archive.join(env)).unwrap();
        for (file, text) in [
            ("REVISION", "0000000000000000000000000000000000000000-test\n"),
            ("THIRD-PARTY-NOTICES", "staged\n"),
            ("LICENSE", "staged\n"),
            ("NOTICES", "staged\n"),
        ] {
            std::fs::write(archive.join(file), text).unwrap();
        }
        let mut files = vec![format!("bin/{}", binary.file_name().unwrap().to_string_lossy())];
        files.extend([unit, env].iter().map(|f| f.to_string_lossy().into_owned()));
        files.extend(["install.sh", "REVISION", "THIRD-PARTY-NOTICES", "LICENSE", "NOTICES"].map(String::from));
        let sums = Command::new("sha256sum").args(&files).current_dir(&archive).output().unwrap();
        assert!(sums.status.success(), "sha256sum");
        std::fs::write(archive.join("SHA256SUMS"), sums.stdout).unwrap();
        archive
    }

    /// The settings this host gives the instance, written before the install,
    /// which keeps a file it finds: the shipped file with `set` lines replaced.
    /// The ports are free ones on loopback, since this host is a test's.
    fn settings(&self, kind: &Kind, set: &[(&str, String)]) {
        let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let mut text = std::fs::read_to_string(repo.join(kind.settings)).unwrap();
        for (key, value) in set {
            let line = text.lines().find(|l| l.starts_with(&format!("{key}="))).unwrap_or_else(|| panic!("{key}")).to_string();
            text = text.replace(&line, &format!("{key}={value}"));
        }
        let at = self.root().join("etc/kotton").join(Path::new(kind.settings).file_name().unwrap());
        std::fs::write(at, text).unwrap();
    }

    /// `KOTTON_PUBLIC_ADDR=127.0.0.1 KOTTON_OPERATOR_KEY=<key> sh install.sh`.
    fn install(&self, archive: &Path, key: &str) -> Output {
        Command::new("/bin/sh")
            .arg(archive.join("install.sh"))
            .env_clear()
            .env("PATH", format!("{}:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", self.dir.join("shims").display()))
            .env("KOTTON_ROOT", self.root())
            .env("KOTTON_PUBLIC_ADDR", "127.0.0.1")
            .env("KOTTON_OPERATOR_KEY", key)
            .stdin(Stdio::null())
            .output()
            .unwrap()
    }

    /// The installed binary, started as its unit starts it — with its installed
    /// settings for an environment — and `under_root` for the directories the
    /// unit names, which this host keeps under its root. Its log is returned.
    fn start(&mut self, kind: &Kind, under_root: &[(&str, PathBuf)]) -> PathBuf {
        let env_file = self.root().join("etc/kotton").join(Path::new(kind.settings).file_name().unwrap());
        let pairs = kvaultd::settings::env_file_pairs(&std::fs::read(&env_file).unwrap()).expect("the installed settings read");
        let log = self.dir.join(format!("{}.log", kind.name));
        let out = std::fs::File::create(&log).unwrap();
        let mut cmd = Command::new(self.root().join("usr/local/bin").join(kind.binary.file_name().unwrap()));
        cmd.env_clear().env("PATH", "/usr/bin:/bin");
        for (k, v) in pairs {
            cmd.env(k, v);
        }
        for (k, dir) in under_root {
            std::fs::create_dir_all(dir).unwrap();
            {
                use std::os::unix::fs::PermissionsExt as _;
                std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
            }
            cmd.env(k, dir);
        }
        let child = cmd.stdin(Stdio::null()).stdout(out.try_clone().unwrap()).stderr(out).spawn().unwrap();
        self.children.push(child);
        log
    }
}

fn said(out: &Output) -> String {
    format!("exit {:?}\nstdout: {}\nstderr: {}", out.status.code(), String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr))
}

/// One line typed at the REPL, through the registry the REPL dispatches on.
async fn typed(state: &mut ShellState, line: &str) -> Vec<Out> {
    let words: Vec<String> = line.split_whitespace().map(str::to_string).collect();
    let executor = kotton_cli::bridge::repl_executor();
    let out = tokio::time::timeout(Duration::from_secs(120), executor.registry().execute(&words[0], &words[1..], state))
        .await
        .unwrap_or_else(|_| panic!("`{line}` did not answer"))
        .unwrap_or_else(|e| panic!("`{line}`: {e:#}"));
    assert!(matches!(out.exit_code, ExitCode::Success), "`{line}` failed: {:?}", out.out);
    out.out
}

/// The one verbatim line a command printed: what a mint says to copy.
fn data(out: &[Out]) -> String {
    let lines: Vec<&String> = out
        .iter()
        .filter_map(|o| match o {
            Out::Data(d) => Some(d),
            _ => None,
        })
        .collect();
    assert_eq!(lines.len(), 1, "one line to copy: {out:?}");
    lines[0].clone()
}

/// The key inside the command a mint printed for `kind`, which names that
/// kind's archive.
fn key_in(command: &str, kind: &str) -> String {
    let (key, install) = command
        .strip_prefix("KOTTON_OPERATOR_KEY=")
        .and_then(|rest| rest.split_once(' '))
        .unwrap_or_else(|| panic!("not the install's command: {command}"));
    assert!(
        install.starts_with(&format!("sh kotton-{kind}-")) && install.ends_with("-linux-x86_64/install.sh"),
        "not the {kind}'s archive: {command}"
    );
    key.to_string()
}

/// **`mint relay` twice, typed at the REPL against a daemon: the second is
/// refused in the daemon's one line, and `mint relay gate` is not**
/// (`TASK-mint-prints-the-hosts-install-command-and-is-verb-first`, Done-when
/// (5) as amended 2026-10-12). The shell sends a nameless mint with no name;
/// the refusal is the daemon's, so removing it there turns this red.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_second_nameless_mint_typed_at_the_repl_is_refused_by_the_daemon() {
    crate::common::init_crypto();
    let mut env = crate::common::relay::env_without().await;
    env.client.create_user(USER, crate::common::TEST_PASSPHRASE).await.expect("create_user");
    let token = env.client.session_token.clone().expect("create_user binds a session");
    let mut client = KottonClient::connect_to(env.endpoint.clone()).await.expect("connect");
    client.authenticate(&token).await.expect("authenticate as the REPL's identity");
    let mut repl = ShellState::new(USER.to_string(), Arc::new(Mutex::new(client)));

    let first = key_in(&data(&typed(&mut repl, "mint relay").await), "relay");
    let executor = kotton_cli::bridge::repl_executor();
    let again = executor.registry().execute("mint", &["relay".to_string()], &mut repl).await;
    let said = match again {
        Err(e) => format!("{e:#}"),
        Ok(out) => panic!("a second `mint relay` was minted: {:?}", out.out),
    };
    assert!(said.contains("you already hold a relay called relay; name this one (`mint relay <name>`)"), "{said}");
    let gate = key_in(&data(&typed(&mut repl, "mint relay gate").await), "relay");
    assert_ne!(first, gate);
}

/// **Mint, request creation, paste the lines: a vault and a relay operated
/// from a desktop with no window, and the vault ends standing at the relay
/// and keeping this person's things** (RFC-0084 V23). Each instance is
/// created by the self-host adapter for the key its mint printed, and its line
/// is the install's last output; the relay's names the address the installer
/// told it. Both lines are pasted once, in one `enrol`, the vault's first:
/// each completes the one key waiting for its kind, with no name, the relay
/// before the vault, so the vault is told where to stand at once — each said
/// as reached and its key matched. The vault's completion ends on the offer,
/// answered yes: `vault invite --me` and the first sync, and the vault's own
/// door says it stands at the relay, by the relay's key, and keeps this
/// person's things; and this device, which stood at no relay, now stands at
/// the relay the same enrol kept
/// (`TASK-enrol-takes-the-lines-an-instance-printed-and-a-vaults-ends-on-an-offer`,
/// Done-when (1), (3)). Then, with one of each held, `relay rule
/// only_my_devices` and `vault people` are typed with no name and each is said
/// to the one instance of its kind.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_headless_desktop_operates_a_vault_and_a_relay_from_the_terminal_alone() {
    crate::common::init_crypto();
    let mut env = crate::common::relay::env_without().await;
    env.client.create_user(USER, crate::common::TEST_PASSPHRASE).await.expect("create_user");
    let token = env.client.session_token.clone().expect("create_user binds a session");
    let mut client = KottonClient::connect_to(env.endpoint.clone()).await.expect("connect");
    client.authenticate(&token).await.expect("authenticate as the REPL's identity");
    let mut repl = ShellState::new(USER.to_string(), Arc::new(Mutex::new(client)));

    // 1. Mint, at the desktop: two keys, the public halves alone.
    let vault_key = key_in(&data(&typed(&mut repl, "mint vault kotton").await), "vault");
    // The relay is minted on its default rule, *only my devices*: the offer's
    // yes is this desktop admitting itself to its own vault through its own
    // relay, and the relay admits it as its operator's device.
    let relay_key = key_in(&data(&typed(&mut repl, "mint relay kotton").await), "relay");
    // A bare `mint` lists both, by kind and — the name not being the kind's
    // word — by name, until each is enrolled.
    let waiting = |out: Vec<Out>| match out.as_slice() {
        [Out::Table { rows, .. }] => rows.clone(),
        other => panic!("{other:?}"),
    };
    let both = waiting(typed(&mut repl, "mint").await);
    assert_eq!(both, vec![vec!["vault".to_string(), "kotton".into()], vec!["relay".into(), "kotton".into()]]);
    for key in [&vault_key, &relay_key] {
        assert!(key.len() == 64 && key.chars().all(|c| c.is_ascii_hexdigit()), "{key}");
    }
    assert_ne!(vault_key, relay_key, "one key per instance (V22)");

    // 2. Request creation of each, for its key: the self-host adapter.
    let mut host = Host::new();
    let relay = Kind {
        name: "relay",
        binary: relay_bin(),
        unit: "infra/relay/kotton-relay.service",
        settings: "infra/relay/relay.env",
    };
    let vault = Kind {
        name: "vault",
        binary: kvaultd_bin(),
        unit: "infra/vault/kotton-vault.service",
        settings: "infra/vault/vault.env",
    };
    let (relay_port, vault_port) = (free_port(), free_port());
    host.settings(&relay, &[
        ("KOTTON_RELAY_BIND", format!("127.0.0.1:{relay_port}")),
        ("KOTTON_RELAY_STUN_BIND", format!("127.0.0.1:{relay_port}")),
    ]);
    host.settings(&vault, &[("KOTTON_PEER_LISTEN_PORT", vault_port.to_string())]);
    let mut lines = Vec::new();
    for (kind, key) in [(&relay, &relay_key), (&vault, &vault_key)] {
        let archive = host.stage(kind);
        let out = host.install(&archive, key);
        assert!(out.status.success(), "{}", said(&out));
        let stdout = String::from_utf8_lossy(&out.stdout);
        let last = stdout.lines().last().unwrap_or_default().to_string();
        let line = InstanceLine::parse(&last).unwrap_or_else(|e| panic!("{e}: {}", said(&out)));
        lines.push(line);
    }
    let (relay_line, vault_line) = (lines[0].clone(), lines[1].clone());
    let relay_url = format!("http://127.0.0.1:{relay_port}");
    assert_eq!((relay_line.kind, relay_line.hint.as_str()), (OperatedService::Relay, relay_url.as_str()), "the relay's line names the address the installer told it");
    assert_eq!((vault_line.kind, vault_line.hint.clone()), (OperatedService::Vault, format!("127.0.0.1:{vault_port}")));

    // …then the systemctl lines the installer names: each started as its unit
    // starts it, from the state creation made.
    let root = host.root();
    host.start(&relay, &[("KOTTON_RELAY_STATE_DIR", root.join("var/lib/kotton-relay"))]);
    let run = root.join("run/kotton-vault");
    let vault_log = host.start(&vault, &[("KOTTON_BASE_DIR", root.join("var/lib/kotton-vault")), ("XDG_RUNTIME_DIR", run.clone())]);
    let deadline = Instant::now() + Duration::from_secs(30);
    while !reqwest::get(format!("{relay_url}/health")).await.is_ok_and(|r| r.status().is_success()) {
        assert!(Instant::now() < deadline, "the relay did not answer /health");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let door = {
        let pairs = kvaultd::settings::env_file_pairs(&std::fs::read(root.join("etc/kotton/vault.env")).unwrap()).unwrap();
        let name = pairs.iter().find(|(k, _)| k == "KVAULTD_IPC_NAME").map(|(_, v)| v.clone()).unwrap_or_else(|| "kvaultd".into());
        let run = run.display().to_string();
        let env = move |k: &str| (k == "XDG_RUNTIME_DIR").then(|| run.clone());
        IpcEndpoint::UnixSocket(kotton_common::paths::daemon_socket_path_in(&env, &name).expect("the vault's door"))
    };
    let mut asked = loop {
        if let Ok(c) = kotton_ipc::IpcClient::<VaultRequest, UserResponse>::connect(door.clone()).await {
            break c;
        }
        assert!(Instant::now() < deadline, "the vault's door did not open:\n{}", std::fs::read_to_string(&vault_log).unwrap_or_default());
        tokio::time::sleep(Duration::from_millis(100)).await;
    };

    // This device stands at no relay before the enrol, so the one it stands at
    // after is the enrol's doing.
    let stands_at = |repl: &ShellState| {
        let client = Arc::clone(&repl.client);
        async move { client.lock().await.node_rendezvous_status().await.expect("this device's relay").url }
    };
    assert_eq!(stands_at(&repl).await, None, "this device stood at a relay before the enrol");

    // 3. Paste both lines once, the vault's first, and take the offer.
    repl.asking = kotton_shell::Asking::Given(["y".to_string()].into());
    let said = typed(&mut repl, &format!("enrol {} {}", vault_line.to_text(), relay_line.to_text())).await;
    let fields = |f: &str| -> Vec<String> {
        said.iter()
            .filter_map(|o| match o {
                Out::Record(rows) => rows.iter().find(|(k, _)| k == f).map(|(_, v)| v.clone()),
                _ => None,
            })
            .collect()
    };
    assert_eq!(fields("enrolled"), vec![
        "you operate the vault 'kotton'; its credential is sealed in your store".to_string(),
        "you operate the relay 'kotton'; its credential is sealed in your store".to_string(),
    ], "each said in the order pasted: {said:?}");
    assert_eq!(fields("reached from here"), vec!["yes".to_string(), "yes".to_string()], "{said:?}");
    assert_eq!(fields("its key"), vec!["matched".to_string(), "matched".to_string()], "{said:?}");
    assert!(fields("not yet standing").is_empty(), "the relay was completed first, so the vault stands: {said:?}");
    assert_eq!(repl.asking, kotton_shell::Asking::Given(Default::default()), "the offer was put");
    assert!(
        said.iter().any(|o| matches!(o, Out::Confirm { action, .. } if action.starts_with("first sync"))),
        "a yes is the invite and the first sync: {said:?}"
    );
    // The yes also stands this device at the relay the same enrol kept, held to
    // its key: said once, nothing said to have failed, and this device's own
    // relay is now the host's.
    assert!(!said.iter().any(|o| matches!(o, Out::Fail { .. })), "the enrol said something failed: {said:?}");
    let stood: Vec<&String> = said
        .iter()
        .filter_map(|o| match o {
            Out::Confirm { action, subject } if action.starts_with("this device stands at your relay too") => Some(subject),
            _ => None,
        })
        .collect();
    assert_eq!(stood, vec![&relay_url], "the yes did not say this device stands at the relay it kept: {said:?}");
    assert_eq!(stands_at(&repl).await, Some(relay_url.clone()), "this device does not stand at the host's relay: {said:?}");
    assert_eq!(waiting(typed(&mut repl, "mint").await), Vec::<Vec<String>>::new(), "each key enrolled is no longer waiting");

    // The vault stands at the relay, by the relay's key — as its own door says.
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        match asked.send(&VaultRequest::NodeRelay { user_id: String::new() }).await.expect("the vault's door answers") {
            UserResponse::NodeRelayResult { relay_url: Some(url), relay_key: Some(key), .. }
                if url == relay_url && key == hex::encode(relay_line.key) =>
            {
                break
            }
            other => assert!(
                Instant::now() < deadline,
                "the vault does not stand at the relay: {other:?}\n{}",
                std::fs::read_to_string(&vault_log).unwrap_or_default()
            ),
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    match asked.send(&VaultRequest::Tenants).await.expect("the vault's door answers") {
        UserResponse::VaultTenants { tenants } => {
            assert!(tenants.iter().any(|t| t.user_id == USER), "the yes did not make this desktop a tenant: {tenants:?}")
        }
        other => panic!("{other:?}"),
    }

    // One relay and one vault held: the operating verbs name neither
    // (`docs/use/run-a-relay.md`, `docs/use/run-a-vault.md`, "Using it").
    let rule = typed(&mut repl, "relay rule only_my_devices").await;
    assert!(
        rule.iter().any(|o| matches!(o, Out::Record(rows) if rows.iter().any(|(k, v)| k == "rule" && v == "only_my_devices"))),
        "`relay rule only_my_devices` was not said to the one relay: {rule:?}"
    );
    let people = typed(&mut repl, "vault people").await;
    match people.as_slice() {
        [Out::Table { rows, .. }] => assert!(rows.iter().any(|r| r[0] == USER), "`vault people` did not list this desktop: {rows:?}"),
        other => panic!("`vault people` was not said to the one vault: {other:?}"),
    }
}
