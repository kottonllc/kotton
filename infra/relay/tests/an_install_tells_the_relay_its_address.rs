// SPDX-License-Identifier: AGPL-3.0-or-later
//! The self-host adapter, `install-server.sh`, writes the address the relay
//! announces into `relay.env` from the host's one address, and the line `create`
//! prints names it (`TASK-the-installer-tells-the-relay-the-address-it-announces`).
//!
//! An archive is laid out here as `cargo xtask release-server relay` packs one —
//! the installer, the built `kotton-relay`, the unit, the settings, the notices
//! and `SHA256SUMS` over them — and installed under `KOTTON_ROOT`. A stand-in
//! `id` says the install runs as an ordinary user, so it makes no user on this
//! machine and runs `create` as whoever runs it; that it runs it as the relay's
//! own user under root is `cargo xtask release-server-test`'s.
#![cfg(target_os = "linux")]

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use kotton_wire::ipc::OperatedService;
use kotton_wire::line::InstanceLine;

#[path = "common/settings_corpus.rs"]
mod corpus;
use corpus::*;

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
        if std::fs::hard_link(env!("CARGO_BIN_EXE_kotton-relay"), archive.join("bin/kotton-relay")).is_err() {
            std::fs::copy(env!("CARGO_BIN_EXE_kotton-relay"), archive.join("bin/kotton-relay")).unwrap();
        }
        std::fs::copy(repo.join("infra/relay/kotton-relay.service"), archive.join("kotton-relay.service")).unwrap();
        std::fs::copy(repo.join("infra/relay/relay.env"), archive.join("relay.env")).unwrap();
        for (file, text) in [
            ("REVISION", "0000000000000000000000000000000000000000-test\n"),
            ("THIRD-PARTY-NOTICES", "staged\n"),
            ("LICENSE", "staged\n"),
            ("NOTICES", "staged\n"),
        ] {
            std::fs::write(archive.join(file), text).unwrap();
        }
        let sums = Command::new("sha256sum")
            .args([
                "bin/kotton-relay",
                "kotton-relay.service",
                "relay.env",
                "install.sh",
                "REVISION",
                "THIRD-PARTY-NOTICES",
                "LICENSE",
                "NOTICES",
            ])
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

    /// The state directory `relay.env` names, under the root.
    fn state(&self) -> PathBuf {
        self.root().join("var/lib/kotton-relay")
    }

    fn settings(&self) -> PathBuf {
        self.root().join("etc/kotton/relay.env")
    }

    fn written(&self) -> String {
        std::fs::read_to_string(self.settings()).unwrap()
    }

    /// `install.sh` with the operator's key, the host's address when given, and
    /// the environment of an ssh session that arrived at `ssh` when given — with
    /// no terminal, as `ssh <host> sh install.sh` runs it.
    fn install(&self, addr: Option<&str>, ssh: Option<&str>) -> Output {
        let mut c = Command::new("/bin/sh");
        c.arg(self.dir.join("archive/install.sh"))
            .env_clear()
            .env("PATH", format!("{}:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", self.dir.join("shims").display()))
            .env("KOTTON_ROOT", self.root())
            .env("KOTTON_OPERATOR_KEY", OPERATOR)
            // A UTF-8 locale, as an ssh session to a host usually carries: the installer's
            // reader must still see bytes, not characters.
            .env("LC_ALL", "C.UTF-8")
            .stdin(Stdio::null());
        if let Some(a) = addr {
            c.env("KOTTON_PUBLIC_ADDR", a);
        }
        if let Some(s) = ssh {
            c.env("SSH_CONNECTION", format!("203.0.113.40 52814 {s} 22"));
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

/// The install's last output, read as the relay's line.
fn the_line(out: &Output) -> InstanceLine {
    assert!(out.status.success(), "{}", said(out));
    let stdout = String::from_utf8_lossy(&out.stdout);
    let last = stdout.lines().last().unwrap_or_default();
    let line = InstanceLine::parse(last).unwrap_or_else(|e| panic!("{e}: {}", said(out)));
    assert_eq!(line.kind, OperatedService::Relay);
    line
}

fn advertise_lines(text: &str) -> Vec<&str> {
    text.lines().filter(|l| l.starts_with("KOTTON_RELAY_ADVERTISE=")).collect()
}

/// **Given the host's address, the install writes `KOTTON_RELAY_ADVERTISE=http://<addr>:7700`
/// into `relay.env`, and the relay's line ends on it** — so nothing is typed at the host
/// to tell the relay where it is.
#[test]
fn an_install_given_the_address_writes_the_url_the_relays_line_names() {
    let staged = Staged::new("advertise-given");
    let line = the_line(&staged.install(Some("relay.example"), None));
    assert_eq!(advertise_lines(&staged.written()), ["KOTTON_RELAY_ADVERTISE=http://relay.example:7700"]);
    assert_eq!(line.hint, "http://relay.example:7700", "the line names the address the settings announce");
}

/// **A value a person set is never replaced, and is what the line names**: a kept
/// `relay.env` whose `KOTTON_RELAY_ADVERTISE` is set keeps it against a different
/// `KOTTON_PUBLIC_ADDR`, and `create` reads the settings, not the address it was given.
/// A kept file whose line is still empty has it filled.
#[test]
fn a_kept_address_is_never_replaced_and_an_empty_one_is_filled() {
    let staged = Staged::new("advertise-kept");
    std::fs::create_dir_all(staged.settings().parent().unwrap()).unwrap();
    let shipped = shipped();
    assert_eq!(advertise_lines(&shipped), ["KOTTON_RELAY_ADVERTISE="], "the shipped settings carry the line, empty");
    let kept = shipped.replace("KOTTON_RELAY_ADVERTISE=\n", "KOTTON_RELAY_ADVERTISE=http://kept.example:7700\n");
    std::fs::write(staged.settings(), &kept).unwrap();

    let out = staged.install(Some("other.example"), None);
    let line = the_line(&out);
    assert_eq!(staged.written(), kept, "a kept relay.env was changed");
    assert_eq!(line.hint, "http://kept.example:7700", "the line names what the settings say, not what the install was given");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("KOTTON_RELAY_ADVERTISE=http://other.example:7700 was not written"), "{}", said(&out));

    // The same kept file with its line empty, over a state directory not yet created.
    std::fs::remove_dir_all(staged.state()).unwrap();
    std::fs::write(staged.settings(), &shipped).unwrap();
    let line = the_line(&staged.install(Some("other.example"), None));
    assert_eq!(advertise_lines(&staged.written()), ["KOTTON_RELAY_ADVERTISE=http://other.example:7700"]);
    assert_eq!(line.hint, "http://other.example:7700");
}

/// **Not given the address, it asks, and writes nothing without a yes**: from an ssh
/// session with no terminal, the install proposes the address the session arrived at,
/// prints the line that writes it, writes none, and says the line is empty.
#[test]
fn not_given_the_address_it_asks_and_writes_nothing_unanswered() {
    let staged = Staged::new("advertise-asked");
    let out = staged.install(None, Some("198.51.100.7"));
    let line = the_line(&out);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let run = format!("KOTTON_PUBLIC_ADDR=198.51.100.7 sh '{}'", staged.dir.join("archive/install.sh").display());
    assert!(stdout.lines().any(|l| l.trim() == run), "it did not print `{run}`: {}", said(&out));
    assert!(stdout.contains("KOTTON_RELAY_ADVERTISE is not set in"), "{}", said(&out));
    assert_eq!(advertise_lines(&staged.written()), ["KOTTON_RELAY_ADVERTISE="], "an address nobody said yes to was written");
    assert_eq!(line.hint, "", "the line names no address nobody gave");
}

/// **An upgrade over a `relay.env` from before the address had a line says so, and
/// asks for it** — the kept settings of every relay installed before this. A line that
/// is absent is read as one that is empty, as systemd reads it: the ssh session's address
/// is proposed, the notice is printed, and given the address the line is added and named.
#[test]
fn an_upgrade_over_settings_with_no_address_line_proposes_it_and_says_so() {
    let staged = Staged::new("advertise-absent");
    std::fs::create_dir_all(staged.settings().parent().unwrap()).unwrap();
    let old: String = shipped().lines().filter(|l| !l.starts_with("KOTTON_RELAY_ADVERTISE=")).map(|l| format!("{l}\n")).collect();
    assert!(advertise_lines(&old).is_empty());
    std::fs::write(staged.settings(), &old).unwrap();

    let out = staged.install(None, Some("198.51.100.7"));
    let line = the_line(&out);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let run = format!("KOTTON_PUBLIC_ADDR=198.51.100.7 sh '{}'", staged.dir.join("archive/install.sh").display());
    assert!(stdout.lines().any(|l| l.trim() == run), "it did not propose the session's address: {}", said(&out));
    assert!(stdout.contains("KOTTON_RELAY_ADVERTISE is not set in"), "it said nothing about the address: {}", said(&out));
    assert_eq!(staged.written(), old, "an address nobody said yes to was written");
    assert_eq!(line.hint, "");

    std::fs::remove_dir_all(staged.state()).unwrap();
    let out = staged.install(Some("relay.example"), None);
    let line = the_line(&out);
    let written = staged.written();
    assert_eq!(advertise_lines(&written), ["KOTTON_RELAY_ADVERTISE=http://relay.example:7700"], "{}", said(&out));
    assert!(written.starts_with(&old), "the kept file was changed rather than added to:\n{written}");
    assert_eq!(line.hint, "http://relay.example:7700");
    assert!(!String::from_utf8_lossy(&out.stdout).contains("is not set in"), "{}", said(&out));
}

/// **A kept value is read as systemd's `EnvironmentFile=` reads it**: one matching pair
/// of quotes around it is not part of it. The address `create` is handed, and the state
/// directory it creates in, are what the unit hands the relay at its start.
#[test]
fn a_kept_value_in_quotes_is_read_as_systemd_reads_it() {
    for (n, q) in ["'", "\"", ""].into_iter().enumerate() {
        let staged = Staged::new(&format!("advertise-quoted-{n}"));
        std::fs::create_dir_all(staged.settings().parent().unwrap()).unwrap();
        let kept = shipped()
            .replace("KOTTON_RELAY_ADVERTISE=\n", &format!("KOTTON_RELAY_ADVERTISE={q}http://kept.example:7700{q}\n"))
            .replace("KOTTON_RELAY_STATE_DIR=/var/lib/kotton-relay\n", &format!("KOTTON_RELAY_STATE_DIR={q}/var/lib/kotton-relay{q}\n"));
        std::fs::write(staged.settings(), &kept).unwrap();
        let out = staged.install(None, None);
        let line = the_line(&out);
        assert_eq!(line.hint, "http://kept.example:7700", "quoted with {q:?}: {}", said(&out));
        assert!(staged.state().is_dir(), "quoted with {q:?}, the state was not made where the unit reads it: {}", said(&out));
        assert_eq!(staged.written(), kept, "a kept relay.env was changed");
        assert!(!String::from_utf8_lossy(&out.stdout).contains("is not set in"), "quoted with {q:?}: {}", said(&out));
    }
}

/// **The address announced is on the port the relay listens on**: a kept
/// `KOTTON_RELAY_BIND` on another port than the port table's is the port written.
#[test]
fn the_announced_port_is_the_one_the_relay_binds() {
    let staged = Staged::new("advertise-port");
    std::fs::create_dir_all(staged.settings().parent().unwrap()).unwrap();
    let kept = shipped().replace("KOTTON_RELAY_BIND=0.0.0.0:7700\n", "KOTTON_RELAY_BIND=\"0.0.0.0:7800\"\n");
    std::fs::write(staged.settings(), &kept).unwrap();
    let out = staged.install(Some("relay.example"), None);
    let line = the_line(&out);
    assert_eq!(advertise_lines(&staged.written()), ["KOTTON_RELAY_ADVERTISE=http://relay.example:7800"], "{}", said(&out));
    assert_eq!(line.hint, "http://relay.example:7800");
}

/// **Of two lines that set it, the last is the one read**, as systemd reads the file:
/// the line `create` prints names the address the unit will hand the relay.
#[test]
fn of_two_lines_that_set_the_address_the_last_is_read() {
    let staged = Staged::new("advertise-twice");
    std::fs::create_dir_all(staged.settings().parent().unwrap()).unwrap();
    let kept = shipped().replace("KOTTON_RELAY_ADVERTISE=\n", "KOTTON_RELAY_ADVERTISE=http://first.example:7700\n")
        + "KOTTON_RELAY_ADVERTISE=http://last.example:7700\n";
    std::fs::write(staged.settings(), &kept).unwrap();
    let line = the_line(&staged.install(None, None));
    assert_eq!(line.hint, "http://last.example:7700");
    assert_eq!(staged.written(), kept);
}

/// **A kept value the installer cannot read in its one plain form is refused, and nothing
/// is installed.** systemd's `EnvironmentFile=` reads more forms than `KEY=value` at the
/// start of a line — indented, spaced around `=`, with a trailing space it trims, after
/// `export` it ignores — and a second reader that missed one would read the person's set
/// value as unset and add a line after it that overrides it. So the installer reads one
/// form, and refuses any other line that names a variable it reads, naming the file, the
/// line and the form to write it in; the file is left byte for byte as it was.
#[test]
fn a_setting_in_any_other_form_than_the_plain_one_is_refused_and_nothing_is_touched() {
    let mut missed = Vec::new();
    for (n, (from, to, refused)) in refused_forms()
    .into_iter()
    .enumerate()
    {
        let staged = Staged::new(&format!("advertise-form-{n}"));
        std::fs::create_dir_all(staged.settings().parent().unwrap()).unwrap();
        let kept = replaced(shipped().as_bytes(), from.as_bytes(), to);
        assert_ne!(kept, shipped().as_bytes());
        std::fs::write(staged.settings(), &kept).unwrap();
        // The line refused: the last of what was put in, or the one the case names.
        let line = if refused.is_empty() { to.split(|b| *b == b'\n').rfind(|l| !l.is_empty()).unwrap() } else { refused };
        let number = kept.split(|b| *b == b'\n').position(|l| l == line).unwrap() + 1;
        let to = String::from_utf8_lossy(to);
        let out = staged.install(Some("other.example"), Some("198.51.100.7"));
        let stderr = String::from_utf8_lossy(&out.stderr);
        let at = format!("{} line {number}", staged.settings().display());
        if out.status.success() || !stderr.contains(&at) {
            // Every form not refused by name is listed at once, not only the first.
            missed.push(format!("{to:?} — {}", said(&out).lines().take(4).collect::<Vec<_>>().join(" / ")));
            continue;
        }
        assert!(stderr.contains("nothing was installed"), "{}", said(&out));
        assert_eq!(std::fs::read(staged.settings()).unwrap(), kept, "{to:?}: the file was touched");
        assert!(!staged.root().join("usr/local/bin/kotton-relay").exists(), "{to:?}: the binary was placed");
        assert!(!staged.state().exists(), "{to:?}: the relay was created");
    }
    assert!(missed.is_empty(), "not refused: {missed:#?}");
}

/// **A kept value set to nothing in quotes is filled, as an empty one is**: `""` and `''`
/// are how systemd spells an empty value too.
#[test]
fn a_kept_address_quoted_empty_is_filled() {
    for (n, q) in ["\"\"", "''"].into_iter().enumerate() {
        let staged = Staged::new(&format!("advertise-quoted-empty-{n}"));
        std::fs::create_dir_all(staged.settings().parent().unwrap()).unwrap();
        let kept = shipped().replace("KOTTON_RELAY_ADVERTISE=\n", &format!("KOTTON_RELAY_ADVERTISE={q}\n"));
        std::fs::write(staged.settings(), &kept).unwrap();
        let line = the_line(&staged.install(Some("relay.example"), None));
        let written = staged.written();
        assert_eq!(advertise_lines(&written), ["KOTTON_RELAY_ADVERTISE=http://relay.example:7700"], "{q}");
        assert_eq!(written, shipped().replace("KOTTON_RELAY_ADVERTISE=\n", "KOTTON_RELAY_ADVERTISE=http://relay.example:7700\n"), "{q}: more than the line changed");
        assert_eq!(line.hint, "http://relay.example:7700");
    }
}

/// **A commented-out line is a comment**: it neither sets the address nor is refused,
/// it is left as it was, and the address is added after it, at the end, under a comment
/// saying who wrote it.
#[test]
fn a_commented_out_address_is_a_comment_and_the_line_is_added_after_it() {
    let staged = Staged::new("advertise-commented");
    std::fs::create_dir_all(staged.settings().parent().unwrap()).unwrap();
    let kept = shipped().replace("KOTTON_RELAY_ADVERTISE=\n", "#KOTTON_RELAY_ADVERTISE=http://old.example:7700\n");
    std::fs::write(staged.settings(), &kept).unwrap();
    let line = the_line(&staged.install(Some("relay.example"), None));
    let written = staged.written();
    assert!(written.starts_with(&kept), "the kept file was changed rather than added to:\n{written}");
    let added: Vec<&str> = written[kept.len()..].lines().filter(|l| !l.is_empty()).collect();
    assert_eq!(added.last(), Some(&"KOTTON_RELAY_ADVERTISE=http://relay.example:7700"), "{written}");
    assert!(added.len() >= 2 && added[..added.len() - 1].iter().all(|l| l.starts_with('#')), "no comment says who added it:\n{written}");
    assert_eq!(line.hint, "http://relay.example:7700");
}

/// **A kept file that does not end in a newline has the address added on a line of its
/// own**, not joined onto its last line.
#[test]
fn the_address_is_added_on_its_own_line_after_a_file_with_no_last_newline() {
    let staged = Staged::new("advertise-no-newline");
    std::fs::create_dir_all(staged.settings().parent().unwrap()).unwrap();
    let kept: String = shipped().lines().filter(|l| !l.starts_with("KOTTON_RELAY_ADVERTISE=")).collect::<Vec<_>>().join("\n");
    assert!(!kept.ends_with('\n'));
    std::fs::write(staged.settings(), &kept).unwrap();
    let line = the_line(&staged.install(Some("relay.example"), None));
    let written = staged.written();
    assert!(written.starts_with(&format!("{kept}\n")), "the kept last line was joined onto:\n{written}");
    assert_eq!(kept.lines().last(), written.lines().nth(kept.lines().count() - 1));
    assert_eq!(advertise_lines(&written), ["KOTTON_RELAY_ADVERTISE=http://relay.example:7700"], "{written}");
    assert_eq!(line.hint, "http://relay.example:7700");
}

/// What the installer reads for each key: its own `setting`, taken from the script, over
/// the same file — the one reader everything it hands `create` passes through.
fn installers_reading(file: &Path, keys: &[&str]) -> Vec<String> {
    let script = std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("../release/install-server.sh")).unwrap();
    let start = script.find("\nsetting() {").expect("install-server.sh has setting()");
    let end = start + script[start..].find("\n}\n").unwrap() + 3;
    let mut program = script[start..end].to_string();
    for key in keys {
        program.push_str(&format!("printf '%s\\n' \"$(setting {key} \"$1\")\"\n"));
    }
    let out = Command::new("/bin/sh").arg("-c").arg(program).arg("sh").arg(file).output().unwrap();
    assert!(out.status.success(), "{}", said(&out));
    String::from_utf8(out.stdout).unwrap().lines().map(str::to_string).collect()
}

/// **The installer and systemd read the same values, checked against systemd's own
/// parser.** Every file the installer accepts gives, for each of the five values it reads,
/// what `load_env_file` gives (no assignment and an empty one alike are "unset" to both);
/// every file it refuses has systemd's reading printed beside it. On a machine without
/// `libsystemd-shared` or `python3` it fails, naming which is missing — unless the run sets
/// `KOTTON_NO_SYSTEMD_PARSER`, and then it is compiled `#[ignore]`d with that reason, so
/// libtest's verdict counts it ignored, by name
/// (`TASK-the-settings-differential-is-not-green-where-systemds-parser-is-absent`).
#[test]
#[cfg_attr(kotton_no_systemd_parser, ignore = "KOTTON_NO_SYSTEMD_PARSER is set: this machine declares it has no systemd parser to compare with")]
fn the_installer_reads_what_systemds_own_parser_reads() {
    use std::io::Write as _;
    const KEYS: [&str; 5] = ["KOTTON_RELAY_ADVERTISE", "KOTTON_RELAY_BIND", "KOTTON_RELAY_STATE_DIR", "KOTTON_PUBLIC_ADDR", "KOTTON_BASE_DIR"];
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("advertise-systemd-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let mut files = Vec::new();
    let accepted = accepted_forms();
    for (n, (_, bytes)) in accepted.iter().enumerate() {
        let f = dir.join(format!("accepted-{n}.env"));
        std::fs::write(&f, bytes).unwrap();
        files.push(f);
    }
    let refused = refused_forms();
    for (n, (from, to, _)) in refused.iter().enumerate() {
        let f = dir.join(format!("refused-{n}.env"));
        std::fs::write(&f, replaced(shipped().as_bytes(), from.as_bytes(), to)).unwrap();
        files.push(f);
    }
    let Some(parser) = systemds_parser_for("the_installer_reads_what_systemds_own_parser_reads") else {
        let _ = std::fs::remove_dir_all(&dir);
        return;
    };
    let (lib, systemd) = systemds_reading(&parser, &files, &KEYS);
    assert_eq!(systemd.len(), files.len(), "{lib}: one reading per file");
    let _ = std::io::stderr().write_all(format!("the_installer_reads_what_systemds_own_parser_reads: compared against {lib}\n").as_bytes());
    let names: Vec<String> = accepted
        .iter()
        .map(|(name, _)| name.to_string())
        .chain(refused.iter().map(|(_, to, _)| format!("{:?}", String::from_utf8_lossy(to))))
        .collect();
    let mut differ = Vec::new();
    let mut report = String::new();
    for (n, file) in files.iter().enumerate() {
        // The installer's verdict is the install's own: run over the file as kept settings.
        let staged = Staged::new(&format!("advertise-systemd-{n}"));
        std::fs::create_dir_all(staged.settings().parent().unwrap()).unwrap();
        std::fs::copy(file, staged.settings()).unwrap();
        let took = staged.install(None, None).status.success();
        let (r, ref values) = systemd[n];
        let name = &names[n];
        if n < accepted.len() && !took {
            differ.push(format!("{name}: the installer refused a file meant to be accepted"));
        }
        if !took {
            report.push_str(&format!("  refused {name}: systemd returned {r}, read {values:?}\n"));
            continue;
        }
        // Accepted: systemd must take the file, and read each value as the installer does.
        if r < 0 {
            differ.push(format!("{name}: the installer accepts it and systemd's parser fails it ({r})"));
            continue;
        }
        let ours = installers_reading(file, &KEYS);
        for (k, key) in KEYS.iter().enumerate() {
            let theirs = values[k].clone().unwrap_or_default();
            if ours[k] != theirs {
                differ.push(format!("{name}: {key} — installer {:?}, systemd {theirs:?}", ours[k]));
            }
        }
    }
    let _ = std::io::stderr().write_all(report.as_bytes());
    assert!(differ.is_empty(), "the installer and {lib} disagree:\n{}\nand on the files it refused, systemd read:\n{report}", differ.join("\n"));
    let _ = std::fs::remove_dir_all(&dir);
}

/// **Generated files, not guessed ones: every file the installer accepts, systemd's own
/// parser accepts and reads the same.** For each of twenty fixed seeds (and
/// `KOTTON_DIFF_SEED`, when set) a seeded generator writes short files — six hundred lines a
/// seed — from key names (the five read among them), `=`, both quotes, a backslash (often
/// ending a line, often before a `;` or `#` line), space, tab, `#`, `;`, `a`, `é` in UTF-8,
/// a `\xff` and newlines. For each one the installer's own checks accept, `load_env_file`
/// must accept it too and give each of the five values as the installer's `setting` does.
/// Each seed and its accepted count are printed. Without `libsystemd-shared` or `python3` it
/// fails, naming which is missing — unless the run sets `KOTTON_NO_SYSTEMD_PARSER`, and then
/// it is compiled `#[ignore]`d with that reason, and libtest counts it ignored, by name.
#[test]
#[cfg_attr(kotton_no_systemd_parser, ignore = "KOTTON_NO_SYSTEMD_PARSER is set: this machine declares it has no systemd parser to compare with")]
fn generated_settings_the_installer_accepts_are_read_the_same_by_systemds_parser() {
    use std::io::Write as _;
    const KEYS: [&str; 5] = ["KOTTON_RELAY_ADVERTISE", "KOTTON_RELAY_BIND", "KOTTON_RELAY_STATE_DIR", "KOTTON_PUBLIC_ADDR", "KOTTON_BASE_DIR"];
    let mut seeds = SEEDS.to_vec();
    if let Some(extra) = std::env::var("KOTTON_DIFF_SEED").ok().and_then(|s| s.parse().ok()) {
        seeds.push(extra);
    }
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("advertise-generated-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let mut files = Vec::new();
    let mut origin = Vec::new();
    for &seed in &seeds {
        for (n, text) in generated_files(seed, 600).into_iter().enumerate() {
            let f = dir.join(format!("seed-{seed}-{n}.env"));
            std::fs::write(&f, &text).unwrap();
            files.push(f);
            origin.push((seed, n));
        }
    }
    let note = format!("seeds {seeds:?}, 600 lines each, {} files; KOTTON_DIFF_SEED=<n> adds one", files.len());
    let Some(parser) = systemds_parser_for("generated_settings_the_installer_accepts_are_read_the_same_by_systemds_parser") else {
        let _ = std::fs::remove_dir_all(&dir);
        return;
    };
    let (lib, systemd) = systemds_reading(&parser, &files, &KEYS);
    let ours = installers_verdicts(&files, &KEYS);
    let mut out = format!("generated_settings_…: compared against {lib}, {note}\n");
    for &seed in &seeds {
        let of_seed: Vec<usize> = (0..files.len()).filter(|&i| origin[i].0 == seed).collect();
        let accepted = of_seed.iter().filter(|&&i| ours[i].is_some()).count();
        out.push_str(&format!("  seed {seed}: {} files, the installer accepted {accepted}\n", of_seed.len()));
        assert!(accepted >= 10, "seed {seed}: too few files accepted ({accepted}) for the comparison to mean much");
    }
    let _ = std::io::stderr().write_all(out.as_bytes());
    let mut differ = Vec::new();
    for (i, verdict) in ours.iter().enumerate() {
        let Some(values) = verdict else { continue };
        let (seed, n) = origin[i];
        let (r, ref theirs) = systemd[i];
        let shown = String::from_utf8_lossy(&std::fs::read(&files[i]).unwrap()).into_owned();
        if r < 0 {
            differ.push(format!("seed {seed} file {n}, accepted, fails systemd's parser ({r}):\n{shown}"));
            continue;
        }
        for (k, key) in KEYS.iter().enumerate() {
            let t = theirs[k].clone().unwrap_or_default();
            if values[k] != t {
                differ.push(format!("seed {seed} file {n}: {key} — installer {:?}, systemd {t:?}:\n{shown}", values[k]));
            }
        }
    }
    assert!(differ.is_empty(), "{lib}: {} disagreement(s):\n{}", differ.len(), differ.iter().take(8).cloned().collect::<Vec<_>>().join("\n---\n"));
    let _ = std::fs::remove_dir_all(&dir);
}
