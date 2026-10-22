// SPDX-License-Identifier: AGPL-3.0-or-later
//! A vault is created for its operator's key, prints its line, and does not
//! start without an operator — the binary, as a host runs it (RFC-0084, the
//! amendment of 2026-10-01: V18, V19, V20).
//!
//! The state directory is under cargo's own temporary directory for this
//! crate's tests, not the system's: a base directory under the system temp dir
//! is a throwaway root to the vault, which then keeps its key in memory, and
//! the key `create` makes would not be the key the start proves. Under it,
//! `KOTTON_SECRETS=file` keeps the key in a `0600` file, as on a host.
#![cfg(target_os = "linux")]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

use kotton_wire::ipc::OperatedService;
use kotton_wire::line::InstanceLine;

const PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
/// ed25519's base point: a key whose secret half nobody here holds.
const OPERATOR: &str = "5866666666666666666666666666666666666666666666666666666666666666";

/// A state directory and a runtime directory of this test's own.
struct Host {
    dir: PathBuf,
    port: u16,
}

impl Host {
    fn new(name: &str) -> Self {
        let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("run")).unwrap();
        let port = std::net::UdpSocket::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        Self { dir, port }
    }

    fn state(&self) -> PathBuf {
        self.dir.join("state")
    }

    /// `kvaultd`, told what a host's unit tells it and nothing of this process.
    fn kvaultd(&self) -> Command {
        self.told(Command::new(env!("CARGO_BIN_EXE_kvaultd")))
    }

    /// [`Host::kvaultd`], exec'd by a shell that first sets `umask`: a umask is
    /// the whole process's, so it is set in the child, never on a test thread.
    fn kvaultd_under_umask(&self, umask: &str) -> Command {
        let mut c = Command::new("/bin/sh");
        c.args(["-c", &format!("umask {umask} && exec \"$0\" \"$@\""), env!("CARGO_BIN_EXE_kvaultd")]);
        self.told(c)
    }

    fn told(&self, mut c: Command) -> Command {
        c.env_clear()
            .env("PATH", PATH)
            .env("KOTTON_SECRETS", "file")
            .env("KOTTON_BASE_DIR", self.state())
            .env("KOTTON_PUBLIC_ADDR", "localhost")
            .env("KOTTON_PEER_LISTEN_PORT", self.port.to_string())
            .env("KVAULTD_IPC_NAME", "vault")
            .env("XDG_RUNTIME_DIR", self.dir.join("run"))
            .env("NO_COLOR", "1")
            .stdin(Stdio::null());
        c
    }

    fn create(&self, operator: &str) -> Output {
        let state = self.state().display().to_string();
        self.kvaultd().args(["create", "--state-dir", &state, "--operator", operator]).output().unwrap()
    }

    /// Start the vault, its stdout and stderr to one log, as the journal keeps them.
    fn start(&self) -> (Child, PathBuf) {
        let log = self.dir.join("vault.log");
        let out = std::fs::File::create(&log).unwrap();
        let child = self.kvaultd().env("RUST_LOG", "info").stdout(out.try_clone().unwrap()).stderr(out).spawn().unwrap();
        (child, log)
    }
}

impl Drop for Host {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn said(out: &Output) -> String {
    format!(
        "exit {:?}\nstdout: {}\nstderr: {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// The start's log once it says it serves, or how it ended.
fn serving(child: &mut Child, log: &Path) -> String {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let text = std::fs::read_to_string(log).unwrap_or_default();
        if text.contains("vault serving") {
            return text;
        }
        if let Ok(Some(status)) = child.try_wait() {
            panic!("kvaultd exited ({status}):\n{text}");
        }
        assert!(Instant::now() < deadline, "kvaultd did not serve in 60 s:\n{text}");
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Every run of hex digits in `bytes` exactly 32 long — the shape of the
/// claim's one-time secret — as text, for the message.
fn tokens_of_32_hex(bytes: &[u8]) -> Vec<String> {
    bytes
        .split(|b| !b.is_ascii_hexdigit())
        .filter(|run| run.len() == 32)
        .map(|run| String::from_utf8_lossy(run).into_owned())
        .collect()
}

/// Every file under `dir` and its bytes, sorted by path.
fn kept(dir: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    let mut all = Vec::new();
    let mut dirs = vec![dir.to_path_buf()];
    while let Some(d) = dirs.pop() {
        for e in std::fs::read_dir(&d).unwrap().flatten() {
            let p = e.path();
            if p.is_dir() {
                dirs.push(p);
            } else if let Ok(bytes) = std::fs::read(&p) {
                all.push((p, bytes));
            }
        }
    }
    all.sort();
    all
}

/// **`kvaultd create` makes the vault for its operator's key and its last
/// output is the vault's line; every start prints that line again; and no
/// 32-hex token appears in anything the vault prints or keeps** (RFC-0084 V18,
/// V20). The line names the key the start proves, and the address the settings
/// announce.
#[test]
fn a_services_start_prints_its_line_and_no_secret() {
    let host = Host::new("line");
    let created = host.create(OPERATOR);
    assert!(created.status.success(), "{}", said(&created));
    let stdout = String::from_utf8_lossy(&created.stdout);
    let last = stdout.lines().last().unwrap_or_default();
    let line = InstanceLine::parse(last).unwrap_or_else(|e| panic!("{e}: {}", said(&created)));
    assert_eq!(line.kind, OperatedService::Vault);
    assert!(line.hint.ends_with(&format!(":{}", host.port)), "the line names the port the settings announce: {last}");

    let (mut child, log) = host.start();
    let text = serving(&mut child, &log);
    assert!(text.lines().any(|l| l == line.to_text()), "the start printed another line than creation's:\n{text}");
    let _ = child.kill();
    let _ = child.wait();

    let mut found = Vec::new();
    for (what, bytes) in [("create's stdout", &created.stdout), ("create's stderr", &created.stderr)] {
        found.extend(tokens_of_32_hex(bytes).into_iter().map(|t| format!("{what}: {t}")));
    }
    found.extend(tokens_of_32_hex(text.as_bytes()).into_iter().map(|t| format!("the start's log: {t}")));
    for (path, bytes) in kept(&host.state()) {
        found.extend(tokens_of_32_hex(&bytes).into_iter().map(|t| format!("{}: {t}", path.display())));
    }
    assert!(found.is_empty(), "a 32-hex token was printed or kept:\n{}", found.join("\n"));
}

/// **A vault whose state names no operator does not start**: it exits
/// non-zero before binding its port or its door, with one sentence naming the
/// state directory and `create --operator`.
#[test]
fn an_instance_with_no_operator_refuses_to_start_and_names_create() {
    let host = Host::new("refused");
    let out = host.kvaultd().output().unwrap();
    assert_eq!(out.status.code(), Some(1), "{}", said(&out));
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(err.trim().lines().count(), 1, "one sentence: {}", said(&out));
    assert!(err.contains(&host.state().display().to_string()), "{}", said(&out));
    assert!(err.contains("kvaultd create --state-dir") && err.contains("--operator <key>"), "{}", said(&out));
    assert!(!host.state().exists(), "the refused start made the state directory");
    assert_eq!(std::fs::read_dir(host.dir.join("run")).unwrap().count(), 0, "the refused start made its door");
    // The port is free: nothing bound it.
    std::net::UdpSocket::bind(("127.0.0.1", host.port)).expect("the peer port is free");
}

/// **`create` is refused while a vault serves on the state, and changes
/// nothing** — the lock the serving vault holds for its whole life.
#[test]
fn create_refuses_while_an_instance_runs_on_the_state() {
    let host = Host::new("held");
    assert!(host.create(OPERATOR).status.success());
    let (mut child, log) = host.start();
    serving(&mut child, &log);
    let out = host.create("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    let _ = child.kill();
    let _ = child.wait();
    assert_eq!(out.status.code(), Some(1), "{}", said(&out));
    assert!(String::from_utf8_lossy(&out.stderr).contains("held by another kvaultd"), "{}", said(&out));
}

/// **`create` refuses a state directory whose key would not outlive it**: under
/// the system's temporary directory a vault's secrets provider is an in-process
/// store, so a key made there is gone when `create` exits and the vault could
/// never start. It exits non-zero, names `KOTTON_SECRETS` and why, and makes
/// nothing.
#[test]
fn create_refuses_a_state_whose_key_would_not_outlive_it() {
    let host = Host::new("throwaway");
    let state = std::env::temp_dir().join(format!("kvaultd-throwaway-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&state);
    let out = host
        .kvaultd()
        .args(["create", "--state-dir", &state.display().to_string(), "--operator", OPERATOR])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1), "{}", said(&out));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("KOTTON_SECRETS") && err.contains("never start"), "{}", said(&out));
    assert!(!state.exists(), "the refused create made the state directory");
}

/// **Whether the key outlives `create` is decided from the real path**: a state
/// directory spelled with `..` that resolves under the system's temporary
/// directory, or reached through a symlinked parent that points there, is the
/// throwaway root it really is — refused, naming `KOTTON_SECRETS`, and nothing
/// left behind. Decided from the spelling, both were written as a vault that
/// could never start.
#[test]
fn create_decides_from_the_real_path_and_refuses_a_throwaway_root_however_spelled() {
    let host = Host::new("spelled");
    let tmp = std::env::temp_dir().canonicalize().unwrap();
    // The assessor's probe: through a directory outside it, then `..`.
    let dotted = format!("/usr/..{}/kvaultd-dotted-{}", tmp.display(), std::process::id());
    let link = host.dir.join("looks-durable");
    std::os::unix::fs::symlink(&tmp, &link).unwrap();
    let linked = link.join(format!("kvaultd-linked-{}", std::process::id()));
    // And parents that did not exist: every directory `create` made goes.
    let deep_top = tmp.join(format!("kvaultd-deep-{}", std::process::id()));
    let deep = deep_top.join("a/b");
    for state in [PathBuf::from(&dotted), linked, deep] {
        let _ = std::fs::remove_dir_all(&state);
        let out = host
            .kvaultd()
            .args(["create", "--state-dir", &state.display().to_string(), "--operator", OPERATOR])
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(1), "{}: {}", state.display(), said(&out));
        assert!(String::from_utf8_lossy(&out.stderr).contains("KOTTON_SECRETS"), "{}", said(&out));
        assert!(!state.exists(), "{} was left behind", state.display());
    }
    assert!(!deep_top.exists(), "a parent create made was left behind");
}

/// **A start under another secrets provider than the vault was created under is
/// refused, naming both** — `create` records the provider it kept the key in,
/// and the start compares, rather than each deriving it from the path at its own
/// moment. Created under `file`, started with no `KOTTON_SECRETS` (the
/// keychain): refused before the runtime is built, and the message says
/// `file` and `keychain`, not that there is no key.
#[test]
fn a_start_under_another_provider_than_creation_is_refused_naming_both() {
    let host = Host::new("provider");
    assert!(host.create(OPERATOR).status.success());
    let recorded = std::fs::read_to_string(host.state().join("system/secrets-provider")).unwrap();
    assert_eq!(recorded.trim(), "file");
    let out = host.kvaultd().env_remove("KOTTON_SECRETS").output().unwrap();
    assert_eq!(out.status.code(), Some(1), "{}", said(&out));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("`file`") && err.contains("`keychain`") && err.contains("KOTTON_SECRETS"), "{}", said(&out));
}

/// **A vault operated before the record existed gets one at its first start**:
/// `create` refuses operated state, so only a start can write it. That start,
/// under the lock, finds the key under its own provider and records it; a
/// later start under another provider is then refused, naming both. The record
/// is never authority — it only ever refuses.
#[test]
fn an_operated_vault_with_no_record_records_its_provider_at_its_first_start() {
    let host = Host::new("unrecorded");
    assert!(host.create(OPERATOR).status.success());
    let record = host.state().join("system/secrets-provider");
    std::fs::remove_file(&record).unwrap();
    let (mut child, log) = host.start();
    serving(&mut child, &log);
    let _ = child.kill();
    let _ = child.wait();
    assert_eq!(std::fs::read_to_string(&record).expect("the start wrote the record").trim(), "file");
    {
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(std::fs::metadata(&record).unwrap().permissions().mode() & 0o777, 0o600);
    }
    let out = host.kvaultd().env_remove("KOTTON_SECRETS").output().unwrap();
    assert_eq!(out.status.code(), Some(1), "{}", said(&out));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("`file`") && err.contains("`keychain`"), "{}", said(&out));
}

/// **The record is written only after the key is found**: an unrecorded vault
/// started under a provider that holds no key for it is refused, and leaves
/// no `system/secrets-provider` behind — a record written before the key was
/// found would name a provider that proved nothing, and refuse the right one
/// at every start after.
#[test]
fn an_unrecorded_start_that_finds_no_key_records_nothing() {
    let host = Host::new("unproved");
    assert!(host.create(OPERATOR).status.success());
    let record = host.state().join("system/secrets-provider");
    std::fs::remove_file(&record).unwrap();
    let out = host.kvaultd().env_remove("KOTTON_SECRETS").output().unwrap();
    assert_eq!(out.status.code(), Some(1), "{}", said(&out));
    assert!(String::from_utf8_lossy(&out.stderr).contains("KOTTON_SECRETS"), "{}", said(&out));
    assert!(!record.exists(), "a start that found no key recorded its provider");
}

/// The permission bits of `path`'s own entry, a symlink's not followed.
fn mode_of(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::symlink_metadata(path).unwrap().permissions().mode() & 0o7777
}

fn set_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

/// Refused in one line on stderr, exit 1, and the line contains `with`.
fn refused_in_one_sentence(out: &Output, with: &str) {
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{}", said(out));
    assert_eq!(err.trim().lines().count(), 1, "one sentence: {}", said(out));
    assert!(err.contains(with), "{}", said(out));
}

/// **(3) `create` refuses a symlinked state directory**
/// (`TASK-kvaultd-create-chmods-any-existing-directory-it-is-pointed-at`):
/// `--state-dir <tmp>/link`, where `link` points at a `0700` directory the
/// test owns, is refused naming `<tmp>/link`, and the directory it points to
/// is still empty and `0700` — the CLI does not canonicalize past it.
#[test]
fn create_refuses_a_symlinked_state_directory() {
    let host = Host::new("symlinked");
    let real = host.dir.join("real");
    std::fs::create_dir(&real).unwrap();
    set_mode(&real, 0o700);
    let link = host.dir.join("link");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    // However the leaf is spelled: a trailing `/` makes the kernel resolve the
    // last component, so `link/` must be read as `link` (the Fable reviewer's
    // refusal of `80b8458da`).
    for spelled in [link.display().to_string(), format!("{}/", link.display())] {
        let out = host.kvaultd().args(["create", "--state-dir", &spelled, "--operator", OPERATOR]).output().unwrap();
        refused_in_one_sentence(&out, &link.display().to_string());
        assert!(String::from_utf8_lossy(&out.stderr).contains("give the directory it points to"), "{spelled}: {}", said(&out));
        assert_eq!(std::fs::read_dir(&real).unwrap().count(), 0, "create wrote through {spelled}");
        assert_eq!(mode_of(&real), 0o700);
    }
}

/// **A start refuses a symlinked state directory, however spelled**: a vault
/// created in `<d>/real`, started with `KOTTON_BASE_DIR` naming `<d>/link` or
/// `<d>/link/`, exits non-zero with "give the directory it points to" and never
/// reaches "vault serving" (the Fable reviewer's refusal of `80b8458da`, where
/// the slashed spelling served).
#[test]
fn a_vault_start_refuses_a_symlinked_state_directory_however_spelled() {
    let host = Host::new("start-symlinked");
    assert!(host.create(OPERATOR).status.success());
    let link = host.dir.join("link");
    std::os::unix::fs::symlink(host.state(), &link).unwrap();
    for spelled in [link.display().to_string(), format!("{}/", link.display())] {
        let log = host.dir.join("start.log");
        let out = std::fs::File::create(&log).unwrap();
        let mut child = host
            .kvaultd()
            .env("KOTTON_BASE_DIR", &spelled)
            .env("RUST_LOG", "info")
            .stdout(out.try_clone().unwrap())
            .stderr(out)
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(30);
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            let text = std::fs::read_to_string(&log).unwrap_or_default();
            if text.contains("vault serving") || Instant::now() > deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("{spelled}: a start through the link served or hung:\n{text}");
            }
            std::thread::sleep(Duration::from_millis(100));
        };
        let text = std::fs::read_to_string(&log).unwrap_or_default();
        assert_eq!(status.code(), Some(1), "{spelled}:\n{text}");
        assert!(text.contains("give the directory it points to") && text.contains(&link.display().to_string()), "{spelled}:\n{text}");
    }
}

/// **(4) `create` makes an absent state directory, and the `system/` it makes
/// in it, `0700`** — under umask `022`, by the mode `mkdir` is given, not by a
/// chmod afterwards.
#[test]
fn create_makes_an_absent_state_directory_0700() {
    let host = Host::new("absent");
    let state = host.state();
    assert!(!state.exists());
    let out = host
        .kvaultd_under_umask("022")
        .args(["create", "--state-dir", &state.display().to_string(), "--operator", OPERATOR])
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", said(&out));
    assert_eq!(mode_of(&state), 0o700, "the state directory");
    assert_eq!(mode_of(&state.join("system")), 0o700, "system/");
}

/// **(6) `create` refuses a `0755` state directory before it opens the
/// secrets provider**: under `KOTTON_SECRETS=file`, over an existing state
/// directory at `0755` holding a `system/secrets.json` that does not parse,
/// `create` prints the `chmod 700` sentence, not the secrets store's error,
/// and leaves the directory `0755` holding only what the test put there.
#[test]
fn create_refuses_a_0755_state_directory_before_it_opens_the_secrets_provider() {
    let host = Host::new("before-secrets");
    let state = host.state();
    std::fs::create_dir_all(state.join("system")).unwrap();
    std::fs::write(state.join("system/secrets.json"), b"this is not a secrets store").unwrap();
    set_mode(&state, 0o755);
    let before = kept(&state);
    let out = host.create(OPERATOR);
    refused_in_one_sentence(&out, &format!("chmod 700 {}", state.display()));
    assert!(!String::from_utf8_lossy(&out.stderr).contains("does not parse"), "{}", said(&out));
    assert_eq!(mode_of(&state), 0o755, "the mode changed");
    assert_eq!(kept(&state), before, "create wrote into the state");
    assert_eq!(std::fs::read_dir(&state).unwrap().count(), 1, "create made something beside system/");
}

/// **A vault's start refuses a `0755` state directory before it opens the
/// secrets provider** (`TASK-the-base-dir-and-system-are-said-to-be-0700-and-nothing-makes-them-so`,
/// (i′)): started bare under `KOTTON_SECRETS=file`, over a created vault whose
/// state directory is then `0755` and whose `system/secrets.json` is then made
/// unparseable, it exits non-zero with the `chmod 700` sentence, not a
/// secrets-store error, and leaves the directory `0755`.
#[test]
fn a_vault_start_refuses_a_0755_state_directory_before_it_opens_the_secrets_provider() {
    let host = Host::new("start-before-secrets");
    assert!(host.create(OPERATOR).status.success());
    let state = host.state();
    set_mode(&state, 0o755);
    std::fs::write(state.join("system/secrets.json"), b"this is not a secrets store").unwrap();
    let out = host.kvaultd().output().unwrap();
    refused_in_one_sentence(&out, &format!("chmod 700 {}", state.display()));
    assert!(!String::from_utf8_lossy(&out.stderr).contains("does not parse"), "{}", said(&out));
    assert_eq!(mode_of(&state), 0o755, "the start changed the mode");
}
