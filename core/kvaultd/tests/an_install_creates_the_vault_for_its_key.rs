// SPDX-License-Identifier: AGPL-3.0-or-later
//! The self-host adapter, `install-server.sh`, creates the vault for the key it
//! is given and ends on the vault's line (RFC-0084 V18, unit 1's Done-when (6)).
//!
//! An archive is laid out here as `cargo xtask release-server` packs one — the
//! installer, the built `kvaultd`, the unit, the settings, the notices and
//! `SHA256SUMS` over them — and installed under `KOTTON_ROOT`. The installer is
//! told it runs as an ordinary user (a stand-in `id`), so it makes no user on
//! this machine and runs `create` as whoever runs it; that it runs it as the
//! vault's own user under root is `cargo xtask release-server-test`'s, with the
//! user database stood in for. The root is under cargo's temporary directory
//! for this crate, not the system's, so the vault's key is kept in a file
//! (`KOTTON_SECRETS=file`) as on a host, and the line names the key a start
//! would prove.
#![cfg(target_os = "linux")]

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use kotton_wire::ipc::OperatedService;
use kotton_wire::line::InstanceLine;

/// ed25519's base point: a key whose secret half nobody here holds.
const OPERATOR: &str = "5866666666666666666666666666666666666666666666666666666666666666";

struct Staged {
    dir: PathBuf,
}

impl Drop for Staged {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

impl Staged {
    /// The archive's files under `<dir>/archive`, an empty root at `<dir>/host`,
    /// and a stand-in `id` at `<dir>/shims`.
    fn new(name: &str) -> Self {
        let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let archive = dir.join("archive");
        std::fs::create_dir_all(archive.join("bin")).unwrap();
        std::fs::create_dir_all(dir.join("host")).unwrap();
        std::fs::create_dir_all(dir.join("shims")).unwrap();
        let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        std::fs::copy(repo.join("infra/release/install-server.sh"), archive.join("install.sh")).unwrap();
        if std::fs::hard_link(env!("CARGO_BIN_EXE_kvaultd"), archive.join("bin/kvaultd")).is_err() {
            std::fs::copy(env!("CARGO_BIN_EXE_kvaultd"), archive.join("bin/kvaultd")).unwrap();
        }
        std::fs::copy(repo.join("infra/vault/kotton-vault.service"), archive.join("kotton-vault.service")).unwrap();
        std::fs::copy(repo.join("infra/vault/vault.env"), archive.join("vault.env")).unwrap();
        for (file, text) in [
            ("REVISION", "0000000000000000000000000000000000000000-test\n"),
            ("THIRD-PARTY-NOTICES", "staged\n"),
            ("LICENSE", "staged\n"),
            ("NOTICES", "staged\n"),
        ] {
            std::fs::write(archive.join(file), text).unwrap();
        }
        let sums = Command::new("sha256sum")
            .args(["bin/kvaultd", "kotton-vault.service", "vault.env", "install.sh", "REVISION", "THIRD-PARTY-NOTICES", "LICENSE", "NOTICES"])
            .current_dir(&archive)
            .output()
            .unwrap();
        assert!(sums.status.success());
        std::fs::write(archive.join("SHA256SUMS"), sums.stdout).unwrap();
        let id = dir.join("shims/id");
        std::fs::write(&id, "#!/bin/sh\ncase \"$1\" in -u) echo 1000 ;; -un) echo someone ;; *) exit 1 ;; esac\n").unwrap();
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&id, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        Self { dir }
    }

    fn root(&self) -> PathBuf {
        self.dir.join("host")
    }

    fn state(&self) -> PathBuf {
        self.root().join("var/lib/kotton-vault")
    }

    fn install(&self, key: Option<&str>) -> Output {
        let mut c = Command::new("/bin/sh");
        c.arg(self.dir.join("archive/install.sh"))
            .env_clear()
            .env("PATH", format!("{}:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", self.dir.join("shims").display()))
            .env("KOTTON_ROOT", self.root())
            .env("KOTTON_PUBLIC_ADDR", "localhost")
            .stdin(Stdio::null());
        if let Some(k) = key {
            c.env("KOTTON_OPERATOR_KEY", k);
        }
        c.output().unwrap()
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

/// Every file under `dir` whose bytes contain `needle`.
fn holding(dir: &Path, needle: &str) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut dirs = vec![dir.to_path_buf()];
    while let Some(d) = dirs.pop() {
        for e in std::fs::read_dir(&d).unwrap().flatten() {
            let p = e.path();
            if p.is_dir() {
                dirs.push(p);
            } else if std::fs::read(&p).is_ok_and(|b| b.windows(needle.len()).any(|w| w == needle.as_bytes())) {
                found.push(p);
            }
        }
    }
    found
}

/// **Given a key, the install creates the vault, starts nothing, and its last
/// output is the vault's line; given none, it creates nothing and says how;
/// run again over a vault that has an operator, it creates nothing and says
/// so** (unit 1's Done-when (6)). The state directory is made `0700`, and the
/// key is written to no file — the operator set keeps it, as bytes.
#[test]
fn an_install_given_a_key_ends_by_printing_the_services_line() {
    let staged = Staged::new("install-none");
    let out = staged.install(None);
    assert!(out.status.success(), "{}", said(&out));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("nothing created") && stdout.contains("KOTTON_OPERATOR_KEY=<the 64 hex"), "{}", said(&out));
    assert!(!staged.state().exists(), "an install given no key made the state directory");
    drop(staged);

    let staged = Staged::new("install-key");
    let out = staged.install(Some(OPERATOR));
    assert!(out.status.success(), "{}", said(&out));
    let stdout = String::from_utf8_lossy(&out.stdout);
    let last = stdout.lines().last().unwrap_or_default();
    let line = InstanceLine::parse(last).unwrap_or_else(|e| panic!("{e}: {}", said(&out)));
    assert_eq!(line.kind, OperatedService::Vault);
    assert!(line.hint.ends_with(":7710"), "the line names the port the settings announce: {last}");
    assert!(stdout.contains("systemctl enable --now kotton-vault"), "{}", said(&out));
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(staged.state()).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "the state directory is the vault's alone");
    }
    assert!(staged.state().join("system/agent.db").exists(), "the vault was created");
    assert!(holding(&staged.root(), OPERATOR).is_empty(), "the key was written to a file: {:?}", holding(&staged.root(), OPERATOR));
    // It started nothing: the state holds no door and no lock is held.
    let lock = std::fs::File::open(staged.state().join("instance.lock")).unwrap();
    lock.try_lock().expect("nothing holds the vault's state after the install");
    drop(lock);

    let again = staged.install(Some("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"));
    assert!(again.status.success(), "{}", said(&again));
    let stdout = String::from_utf8_lossy(&again.stdout);
    assert!(stdout.contains("already holds a vault that has an operator"), "{}", said(&again));
    assert!(InstanceLine::parse(stdout.lines().last().unwrap_or_default()).is_err(), "a second install printed a line: {}", said(&again));
}

/// **The vault's settings are read in the one plain form too, and any other is refused
/// before anything is written** (`TASK-the-installer-tells-the-relay-the-address-it-announces`):
/// a kept `KOTTON_PUBLIC_ADDR` spaced around `=` read as unset would have had a second
/// line added after it, which systemd reads over the person's.
#[test]
fn a_kept_vault_setting_in_another_form_is_refused_and_left_as_it_was() {
    let shipped = std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../infra/vault/vault.env")).unwrap();
    for (n, (from, to)) in [
        ("KOTTON_PUBLIC_ADDR=\n", "KOTTON_PUBLIC_ADDR = 192.0.2.7\n"),
        ("KOTTON_BASE_DIR=/var/lib/kotton-vault\n", "  KOTTON_BASE_DIR=/var/lib/kotton-vault\n"),
    ]
    .into_iter()
    .enumerate()
    {
        let staged = Staged::new(&format!("vault-form-{n}"));
        let settings = staged.root().join("etc/kotton/vault.env");
        std::fs::create_dir_all(settings.parent().unwrap()).unwrap();
        let kept = shipped.replace(from, to);
        assert_ne!(kept, shipped);
        std::fs::write(&settings, &kept).unwrap();
        let out = staged.install(None);
        assert!(!out.status.success(), "{to:?} was not refused: {}", said(&out));
        let number = kept.lines().position(|l| l == to.trim_end_matches('\n')).unwrap() + 1;
        let at = format!("{} line {number}", settings.display());
        assert!(String::from_utf8_lossy(&out.stderr).contains(&at), "{to:?}: the refusal does not name {at}: {}", said(&out));
        assert_eq!(std::fs::read(&settings).unwrap(), kept.as_bytes(), "{to:?}: the file was touched");
        assert!(!staged.root().join("usr/local/bin/kvaultd").exists(), "{to:?}: the binary was placed");
    }
}

/// **A kept `KOTTON_PUBLIC_ADDR` in quotes — a form the installer reads — is the address
/// the vault's line names** (`TASK-the-vaults-own-reader-of-its-settings-reads-the-plain-form-the-installer-admits`).
/// `vault.env` has three readers: the installer, systemd, and `kvaultd` itself, which
/// `create` reads the address through. All three take one matching pair of quotes off.
#[test]
fn a_kept_vault_address_in_quotes_installs_and_the_line_names_it() {
    let shipped = std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../infra/vault/vault.env")).unwrap();
    for (n, q) in ["\"", "'"].into_iter().enumerate() {
        let staged = Staged::new(&format!("vault-quoted-{n}"));
        let settings = staged.root().join("etc/kotton/vault.env");
        std::fs::create_dir_all(settings.parent().unwrap()).unwrap();
        let kept = shipped.replace("KOTTON_PUBLIC_ADDR=\n", &format!("KOTTON_PUBLIC_ADDR={q}192.0.2.7{q}\n"));
        assert_ne!(kept, shipped);
        std::fs::write(&settings, &kept).unwrap();
        let out = staged.install(Some(OPERATOR));
        assert!(out.status.success(), "quoted with {q}: {}", said(&out));
        let stdout = String::from_utf8_lossy(&out.stdout);
        let last = stdout.lines().last().unwrap_or_default();
        let line = InstanceLine::parse(last).unwrap_or_else(|e| panic!("{e}: {}", said(&out)));
        assert_eq!(line.hint, "192.0.2.7:7710", "quoted with {q}: {last}");
        assert_eq!(std::fs::read_to_string(&settings).unwrap(), kept, "a kept vault.env was changed");
    }
}
