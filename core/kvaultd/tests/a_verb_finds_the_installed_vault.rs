// SPDX-License-Identifier: AGPL-3.0-or-later
//! A `kvaultd` verb typed bare at a host's shell finds the vault running there
//! (`TASK-a-kvaultd-verb-at-the-boxs-shell-finds-the-running-vault-only-with-its-env-file-sourced`).
//!
//! The host is a directory laid out as `install.sh` lays out `/` under
//! `KOTTON_ROOT`: the binary at `usr/local/bin/kvaultd`, the repository's
//! `vault.env` at `etc/kotton/vault.env` with its paths pointed into the
//! directory. The daemon is started from that file as the unit starts it; each
//! verb is run with an environment of `PATH` and a login's `XDG_RUNTIME_DIR`,
//! which names a directory the door is not in — nothing is sourced.
//!
//! **No verb here can exec a binary some process holds open for writing.** The two
//! tests run on threads of one process, and a fork copies every descriptor open at
//! that instant — `O_CLOEXEC` closes them only at the child's exec. So a spawn on one
//! thread while the other is writing its host's `kvaultd` gives the child a write
//! descriptor to that file, and an exec of it until that child execs fails with
//! `ETXTBSY` (`TASK-the-installed-vault-tests-exec-a-kvaultd-copy-a-sibling-tests-fork-may-still-hold-open`).
//! [`Host::installed`] hard-links the built binary, so no write descriptor exists at
//! all. Where it cannot — the temporary directory on another filesystem — it copies,
//! and the copy is opened, written and closed under [`FORKS`] held for writing, while
//! every spawn in this file holds it for reading: no fork happens while the copy is open.
#![cfg(target_os = "linux")]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::RwLock;
use std::time::{Duration, Instant};

const PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

/// The operator each host's vault is created for: ed25519's base point, a key
/// whose secret half nobody here holds.
const CREATOR: &str = "5866666666666666666666666666666666666666666666666666666666666666";

/// Held for reading across every spawn in this file, and for writing across the one
/// thing here that opens an executable for writing: the fallback copy in
/// [`Host::installed`].
static FORKS: RwLock<()> = RwLock::new(());

/// `f`, which spawns, with no copy of a binary open meanwhile.
fn forked<T>(f: impl FnOnce() -> T) -> T {
    let _held = FORKS.read().unwrap_or_else(|e| e.into_inner());
    f()
}

/// The built `kvaultd` at `to`: a hard link where the filesystem allows, so nothing is
/// ever open for writing; otherwise a copy closed before any spawn can fork.
/// The link is cargo's own inode: set no mode or owner on the host's `kvaultd`, or the
/// built binary changes with it.
fn install_binary(to: &Path) {
    let built = env!("CARGO_BIN_EXE_kvaultd");
    if std::fs::hard_link(built, to).is_ok() {
        return;
    }
    let _held = FORKS.write().unwrap_or_else(|e| e.into_inner());
    std::fs::copy(built, to).unwrap();
}

struct Host {
    _dir: tempfile::TempDir,
    root: PathBuf,
}

impl Host {
    /// The binary and the repository's `vault.env`, installed under a fresh root,
    /// the file's paths and port pointed into it.
    fn installed() -> Self {
        Self::installed_at("")
    }

    /// [`Host::installed`], its root `sub` below the temporary directory.
    fn installed_at(sub: &str) -> Self {
        // Under cargo's own temporary directory, not the system's: a base
        // directory under the system's is a throwaway root to the vault, whose
        // key then lives in memory and is gone between `create` and the start —
        // and a start never makes a key over existing state.
        let dir = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
        let root = dir.path().join(sub);
        let bin = root.join("usr/local/bin");
        std::fs::create_dir_all(&bin).unwrap();
        install_binary(&bin.join("kvaultd"));
        for d in ["var/lib/kotton-vault", "run/kotton-vault", "etc/kotton"] {
            std::fs::create_dir_all(root.join(d)).unwrap();
        }
        // The state directory as a host has it: `0700`, as the installer
        // (`install -d -m 0700`) and the unit (`StateDirectoryMode=0700`) make
        // it. `create` uses an existing one only so, and chmods nothing
        // (`TASK-kvaultd-create-chmods-any-existing-directory-it-is-pointed-at`).
        {
            use std::os::unix::fs::PermissionsExt as _;
            let state = root.join("var/lib/kotton-vault");
            std::fs::set_permissions(state, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let shipped = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../infra/vault/vault.env");
        let edits = [
            ("KOTTON_BASE_DIR", root.join("var/lib/kotton-vault").display().to_string()),
            ("XDG_RUNTIME_DIR", root.join("run/kotton-vault").display().to_string()),
            ("KOTTON_PEER_LISTEN_PORT", free_udp_port().to_string()),
            ("KOTTON_PUBLIC_ADDR", "127.0.0.1".to_string()),
        ];
        // Each edited value is written quoted, as a person may write it: every reader
        // here — the daemon's, the verbs' and this file's own — takes one wrapping pair
        // of quotes off (`TASK-release-server-tests-reader-of-the-env-file-is-not-the-plain-form`).
        let mut text = String::new();
        for line in std::fs::read_to_string(shipped).unwrap().lines() {
            match edits.iter().find(|(k, _)| line.starts_with(&format!("{k}="))) {
                Some((k, v)) => text.push_str(&format!("{k}=\"{v}\"\n")),
                None => text.push_str(&format!("{line}\n")),
            }
        }
        std::fs::write(root.join("etc/kotton/vault.env"), text).unwrap();
        Self { _dir: dir, root }
    }

    fn bin(&self) -> PathBuf {
        self.root.join("usr/local/bin/kvaultd")
    }

    fn env_file(&self) -> PathBuf {
        self.root.join("etc/kotton/vault.env")
    }

    /// The env file's settings in order, read by the vault's own reader
    /// (`kvaultd::settings::env_file_pairs`) — the one plain form the installer, systemd
    /// and every `kvaultd` verb read — and a file in another form refused, never trimmed
    /// (`TASK-release-server-tests-reader-of-the-env-file-is-not-the-plain-form`).
    fn settings(&self) -> Vec<(String, String)> {
        let file = self.env_file();
        kvaultd::settings::env_file_pairs(&std::fs::read(&file).unwrap()).unwrap_or_else(|why| panic!("{}: {why}", file.display()))
    }

    /// The door the daemon binds: its own rule over the env file it is started with,
    /// so a root too deep for `sun_path` finds the short path the vault falls back to
    /// (`TASK-release-server-test-looks-for-the-vaults-door-where-a-long-checkout-path-does-not-put-it`).
    fn door(&self) -> PathBuf {
        let pairs = self.settings();
        let env = |key: &str| pairs.iter().rev().find(|(k, _)| k == key).map(|(_, v)| v.clone());
        kotton_common::paths::daemon_socket_path_in(&env, &env("KVAULTD_IPC_NAME").unwrap()).unwrap()
    }

    /// The daemon, told by the env file and nothing else — `EnvironmentFile=`, as
    /// [`Host::settings`] reads it —
    /// once the vault is created for an operator's key, typed bare as the
    /// self-host adapter types it: a vault does not start without one
    /// (RFC-0084 V18, V19).
    fn start(&self, uid: Option<u32>) -> Running {
        let base = self.root.join("var/lib/kotton-vault").display().to_string();
        let created = typed(&self.bin(), uid, &[], &["create", "--state-dir", &base, "--operator", CREATOR]);
        assert!(created.status.success(), "{}", said(&created));
        let mut cmd = as_uid(&self.bin(), uid);
        for (k, v) in self.settings() {
            cmd.env(k, v);
        }
        let log = self.root.join("vault.log");
        let out = std::fs::File::create(&log).unwrap();
        cmd.stdout(out.try_clone().unwrap()).stderr(out);
        // Named before the spawn, so a daemon that binds and then dies still has its
        // directory removed by the unwind.
        let fallback_dir = kotton_common::paths::daemon_socket_fallback_dir(&self.door()).map(Path::to_path_buf);
        let child = forked(|| cmd.spawn()).unwrap();
        let mut running = Running { child, fallback_dir };
        let deadline = Instant::now() + Duration::from_secs(60);
        while !std::fs::read_to_string(&log).unwrap_or_default().contains("vault serving") {
            if let Ok(Some(status)) = running.child.try_wait() {
                panic!("kvaultd exited ({status}):\n{}", std::fs::read_to_string(&log).unwrap_or_default());
            }
            assert!(Instant::now() < deadline, "kvaultd did not serve in 60 s");
            std::thread::sleep(Duration::from_millis(100));
        }
        running
    }
}

/// A started daemon, and the `/tmp/kotton-<key>/` directory its door is in when the
/// host was too deep for the door to be joined under it.
///
/// Dropping it stops the daemon and then removes that directory: the daemon made it
/// at bind and leaves it, as it should on a host, but this host's `TempDir` cannot reach
/// it, so until 2026-09-28 every run of the too-deep test left one behind
/// (`TASK-the-deep-box-vault-test-leaves-its-short-door-in-tmp`). A door inside the
/// host goes with the host.
struct Running {
    child: Child,
    fallback_dir: Option<PathBuf>,
}

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(dir) = self.fallback_dir.take() {
            let _ = std::fs::remove_dir_all(dir);
        }
    }
}

/// `bin`, with nothing of this process's environment but `PATH`; as `uid` through
/// `setpriv` when given, its group the same number and no other.
fn as_uid(bin: &Path, uid: Option<u32>) -> Command {
    let mut c = match uid {
        Some(n) => {
            let mut c = Command::new("setpriv");
            c.args(["--reuid", &n.to_string(), "--regid", &n.to_string(), "--clear-groups"]).arg(bin);
            c
        }
        None => Command::new(bin),
    };
    c.env_clear().env("PATH", PATH).stdin(Stdio::null());
    c
}

/// A verb as a person at the host's shell types it: `PATH` and their login's
/// `XDG_RUNTIME_DIR`, `/run/user/<uid>`, and whatever `extra` names.
fn typed(bin: &Path, uid: Option<u32>, extra: &[(&str, &str)], args: &[&str]) -> Output {
    let mut c = typed_as(bin, uid, extra, args);
    forked(|| c.output()).unwrap()
}

/// [`typed`], with no extra environment, for a verb that must end by itself:
/// one still running after `within` is killed and the test fails saying so,
/// rather than waiting on it (#112).
fn typed_within(within: Duration, bin: &Path, args: &[&str]) -> Output {
    let mut c = typed_as(bin, None, &[], args);
    c.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = forked(|| c.spawn()).unwrap();
    let deadline = Instant::now() + within;
    while child.try_wait().unwrap().is_none() {
        if Instant::now() > deadline {
            let _ = child.kill();
            let out = child.wait_with_output().unwrap();
            panic!("`kvaultd {}` had not exited after {within:?}: {}", args.join(" "), said(&out));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    child.wait_with_output().unwrap()
}

fn typed_as(bin: &Path, uid: Option<u32>, extra: &[(&str, &str)], args: &[&str]) -> Command {
    let mut c = as_uid(bin, uid);
    c.env("XDG_RUNTIME_DIR", format!("/run/user/{}", uid.unwrap_or(0)));
    for (k, v) in extra {
        c.env(k, v);
    }
    c.args(args);
    c
}

fn said(out: &Output) -> String {
    format!(
        "exit {:?}\nstdout: {}\nstderr: {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// Refused in exactly one line on stderr, exit 1, and the line contains `with`.
fn refused_in_one_sentence(out: &Output, with: &str) {
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(1), "{}", said(out));
    assert_eq!(err.trim().lines().count(), 1, "one sentence: {}", said(out));
    assert!(err.contains(with), "{}", said(out));
}

fn free_udp_port() -> u16 {
    std::net::UdpSocket::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

/// A uid for the daemon and the verb to run as, when this runs as root: one no user
/// and no group of this machine has. `None` otherwise, and the as-its-user half is
/// skipped — `cargo xtask release-server-test` holds it too.
fn service_uid() -> Option<u32> {
    let me = forked(|| Command::new("id").arg("-u").output()).ok()?;
    if String::from_utf8_lossy(&me.stdout).trim() != "0" {
        return None;
    }
    forked(|| Command::new("setpriv").arg("--version").output()).ok().filter(|o| o.status.success())?;
    (64_300..64_400u32).find(|n| {
        ["passwd", "group"].iter().all(|db| {
            forked(|| Command::new("getent").args([db, &n.to_string().as_str()]).stdout(Stdio::null()).status())
                .is_ok_and(|s| !s.success())
        })
    })
}

#[test]
fn a_verb_typed_bare_reaches_the_installed_vault_and_is_refused_in_one_sentence_when_none_runs() {
    let b = Host::installed();
    let door = b.door().display().to_string();

    // Nothing running: refused, naming the door vault.env names — so the file was read.
    refused_in_one_sentence(&typed(&b.bin(), None, &[], &["tenants"]), &format!("no vault is running here: nothing answers at {door}"));

    let vault = b.start(None);
    // Running: `tenants` and `capacity` reach it, typed bare.
    let out = typed(&b.bin(), None, &[], &["tenants"]);
    assert!(out.status.success(), "{}", said(&out));
    assert!(String::from_utf8_lossy(&out.stdout).contains("this vault keeps for no one"), "{}", said(&out));
    let out = typed(&b.bin(), None, &[], &["capacity", "nobody"]);
    assert!(out.status.success(), "{}", said(&out));
    // `drop` reaches it too: it asks the door who is kept, and nobody is.
    refused_in_one_sentence(&typed(&b.bin(), None, &[], &["drop", "nobody", "--yes"]), "keeps nothing under 'nobody'");
    // `operator enrol`, typed bare, prints the vault's line, naming the address vault.env
    // names — the host's one address and the peer port. The key is ed25519's base point.
    let key = "5866666666666666666666666666666666666666666666666666666666666666";
    let out = typed(&b.bin(), None, &[], &["operator", "enrol", key]);
    assert!(out.status.success(), "{}", said(&out));
    let port = b.settings().into_iter().rev().find(|(k, _)| k == "KOTTON_PEER_LISTEN_PORT").unwrap().1;
    let stdout = String::from_utf8_lossy(&out.stdout);
    let line = kotton_wire::line::InstanceLine::parse(stdout.lines().last().unwrap_or_default()).unwrap_or_else(|e| panic!("{e}: {}", said(&out)));
    assert_eq!(line.hint, format!("127.0.0.1:{port}"), "{}", said(&out));
    assert!(!stdout.contains("vault=") && !stdout.contains("addr="), "the lines the line replaced: {}", said(&out));
    // `operator` revoke reaches it too: every credential but the one kept is the
    // vault's answer, and `--all` alone is refused before the door is asked —
    // a vault is never left with none (RFC-0084 V19, fork 3).
    let out = typed(&b.bin(), None, &[], &["operator", "revoke", "--all"]);
    assert_eq!(out.status.code(), Some(2), "{}", said(&out));
    let out = typed(&b.bin(), None, &[], &["operator", "revoke", "--all", "--keep", CREATOR]);
    assert!(out.status.success(), "{}", said(&out));
    assert!(String::from_utf8_lossy(&out.stdout).contains("only the operator credential named has standing"), "{}", said(&out));
    // `invite` reaches it too. This vault stands at no relay — nobody's desktop has
    // told it where — so it mints nothing and says why in one sentence: the act
    // that tells it, and no file
    // (TASK-kvaultd-invite-at-a-vault-with-no-relay-says-only-that-the-ceremony-closed,
    // TASK-the-desktop-tells-the-vault-which-relays-to-stand-at).
    // Each refusal of an invite ends the door's stream after it, so the verb
    // ends by itself — whatever it names (#112).
    let out = typed_within(Duration::from_secs(60), &b.bin(), &["invite", "sam", "--ttl", "5"]);
    refused_in_one_sentence(&out, "this vault stands at no relay");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("`enrol <the vault's line>`"), "{}", said(&out));
    assert!(!err.contains("vault.env"), "{}", said(&out));
    assert!(!String::from_utf8_lossy(&out.stdout).contains("invite="), "{}", said(&out));
    // A name the vault keeps is refused before the relay is looked for: the
    // vault's typed answer (`VaultKeepsAlready`, #108), said in one sentence,
    // exit 1. `sam` is written into the registry the vault reads at each invite
    // (`keeps_someone_as`), as a join's save writes it. The verb reads neither
    // this answer nor the one above by name (#114): it says what is not the
    // ceremony once the door ends the stream, and here it must end.
    let system = b.root.join("var/lib/kotton-vault/system");
    let mut registry = kotton_device::registry::load_users(&system).unwrap();
    registry.users.push(
        serde_json::from_value(serde_json::json!({
            "user_id": "sam",
            "did": "did:kel:sam",
            "created_at": { "secs_since_epoch": 1, "nanos_since_epoch": 0 },
            "last_active": { "secs_since_epoch": 1, "nanos_since_epoch": 0 },
        }))
        .unwrap(),
    );
    kotton_device::registry::save_users(&system, &registry).unwrap();
    let out = typed_within(Duration::from_secs(60), &b.bin(), &["invite", "sam", "--ttl", "5"]);
    refused_in_one_sentence(&out, "this vault already keeps for 'sam' — an invite admits someone new");
    assert!(!String::from_utf8_lossy(&out.stdout).contains("invite="), "{}", said(&out));

    // `join` reaches it too, and ends by itself on a code that is not one: the
    // vault refuses it before any ceremony, in its own words, and the door
    // closes after them. The verb names no refusal (#121): it says what is not
    // the ceremony once the stream ends — said, not dropped for "closed the
    // ceremony without a result".
    let out = typed_within(Duration::from_secs(60), &b.bin(), &["join", "sam", "not-a-code"]);
    refused_in_one_sentence(&out, "connection code");
    assert!(!String::from_utf8_lossy(&out.stderr).contains("without a result"), "{}", said(&out));

    // The same binary outside an install reads no file, and looks where the login says.
    let out = typed(Path::new(env!("CARGO_BIN_EXE_kvaultd")), None, &[], &["tenants"]);
    refused_in_one_sentence(&out, "nothing answers at /run/user/0/kotton/kvaultd.sock");
    // A caller who names a door gets that door, and the file is not read.
    let out = typed(&b.bin(), None, &[("KVAULTD_IPC_NAME", "elsewhere")], &["tenants"]);
    refused_in_one_sentence(&out, "nothing answers at /run/user/0/kotton/elsewhere.sock");

    drop(vault);
    refused_in_one_sentence(&typed(&b.bin(), None, &[], &["tenants"]), &format!("no vault is running here: nothing answers at {door}"));
}

/// As the vault's own user: the daemon runs as that uid, its directories are its
/// own and 0700, the env file is root's and that uid's group's to read, 0640, as
/// `install.sh` leaves it — and the verb, typed bare as that uid, reaches the door.
/// With the file 0600, root's alone, the verb says so in one sentence rather than
/// looking for a door nobody made.
#[test]
fn a_verb_typed_as_the_vaults_own_user_reaches_it_through_the_files_group() {
    use std::os::unix::fs::PermissionsExt as _;
    let Some(n) = service_uid() else {
        eprintln!("skipped: not root, or no setpriv — nothing to run as the vault's uid");
        return;
    };
    let b = Host::installed();
    for d in ["var/lib/kotton-vault", "run/kotton-vault"] {
        let d = b.root.join(d);
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::os::unix::fs::chown(&d, Some(n), Some(n)).unwrap();
    }
    // The root the test made is 0700 root's; the uid must be able to reach the binary
    // and the file under it, as it can reach /usr/local/bin and /etc on a host. Only the
    // test's own directory is opened: its parent is this machine's temporary directory,
    // which every uid already traverses, and is never touched.
    std::fs::set_permissions(&b.root, std::fs::Permissions::from_mode(0o755)).unwrap();
    let env = b.env_file();
    std::os::unix::fs::chown(&env, Some(0), Some(n)).unwrap();
    std::fs::set_permissions(&env, std::fs::Permissions::from_mode(0o640)).unwrap();

    let _vault = b.start(Some(n));
    let out = typed(&b.bin(), Some(n), &[], &["tenants"]);
    assert!(out.status.success(), "{}", said(&out));
    assert!(String::from_utf8_lossy(&out.stdout).contains("this vault keeps for no one"), "{}", said(&out));
    // Root reaches the uid's door as well.
    let out = typed(&b.bin(), None, &[], &["tenants"]);
    assert!(out.status.success(), "{}", said(&out));

    std::fs::set_permissions(&env, std::fs::Permissions::from_mode(0o600)).unwrap();
    refused_in_one_sentence(
        &typed(&b.bin(), Some(n), &[], &["tenants"]),
        &format!("cannot read {}", env.display()),
    );
}

/// A host whose root is deep enough that `run/kotton-vault/kotton/vault.sock` will not
/// bind — a checkout at `.claude/worktrees/<name>` puts the release test's host that
/// deep — still has one door, and the daemon, the verb and [`Host::door`] all name it:
/// the short path `daemon_socket_path` falls back to, not the joined one
/// (`TASK-release-server-test-looks-for-the-vaults-door-where-a-long-checkout-path-does-not-put-it`).
#[test]
fn a_box_too_deep_for_its_joined_door_is_reached_at_the_door_the_vault_opened() {
    let b = Host::installed_at(&"d".repeat(60));
    let joined = b.root.join("run/kotton-vault/kotton/vault.sock");
    assert!(joined.as_os_str().len() > 103, "{} is not deep enough", joined.display());
    let door = b.door();
    assert_ne!(door, joined, "the door was joined by hand");

    let vault = b.start(None);
    use std::os::unix::fs::FileTypeExt as _;
    let kind = std::fs::metadata(&door).unwrap_or_else(|e| panic!("{}: {e}", door.display())).file_type();
    assert!(kind.is_socket(), "{} is not the vault's socket", door.display());
    assert!(!joined.exists(), "{} exists, and nothing could bind it", joined.display());
    let out = typed(&b.bin(), None, &[], &["tenants"]);
    assert!(out.status.success(), "{}", said(&out));
    assert!(String::from_utf8_lossy(&out.stdout).contains("this vault keeps for no one"), "{}", said(&out));
    drop(vault);
    refused_in_one_sentence(
        &typed(&b.bin(), None, &[], &["tenants"]),
        &format!("no vault is running here: nothing answers at {}", door.display()),
    );
    // The door's directory is outside the host, so the host's `TempDir` cannot take it;
    // the vault's drop did (`TASK-the-deep-box-vault-test-leaves-its-short-door-in-tmp`).
    let dir = door.parent().unwrap();
    assert!(!dir.starts_with(&b.root), "{} is inside the host", dir.display());
    assert!(!dir.exists(), "{} outlived the vault", dir.display());
}
