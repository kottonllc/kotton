// SPDX-License-Identifier: AGPL-3.0-or-later
//! `cargo xtask release-server relay|vault|host` and `cargo xtask release-server-test` —
//! the relay and the vault, each released as one archive a host installs under systemd, and
//! the two together as the host's archive, for the one machine that runs both.
//!
//! `DEC-0085`, `TASK-the-relay-and-the-vault-are-each-a-release-a-box-installs-under-systemd`.
//! A release is a binary and its checksum: no image, no registry, no Docker. It follows
//! the desktop's release (`release.rs`) — one directory, `REVISION`, `install.sh`, a test
//! that installs the archive before it is named, and the archive's sha256 printed — with a
//! systemd unit, the env file the unit reads, and `SHA256SUMS` in place of the desktop's
//! launcher and shell.
//!
//! ## The layout
//!
//! ```text
//! kotton-<name>-<rev>-linux-<arch>/
//!   bin/<binary>         the one executable: kotton-relay, or kvaultd
//!   kotton-<name>.service  the unit install.sh places in /etc/systemd/system
//!   <name>.env           its settings, placed once in /etc/kotton and never overwritten
//!   install.sh           checks SHA256SUMS, places the three, prints the systemctl lines
//!   REVISION             the commit, and the target the binary was built for
//!   THIRD-PARTY-NOTICES  every dependency the binary is built from, its version, its
//!                        license and its license texts — from the lockfile, never by hand
//!   LICENSE              Kotton's own license, and
//!   NOTICES              its notice, the repository root's (`release::OWN`)
//!   SHA256SUMS           every file above
//! ```
//!
//! The host's archive holds both trees whole, each as its own archive lays it out, beside an
//! installer that runs the two trees' own ([`HOST_INSTALLER`], [`host_entries`]):
//!
//! ```text
//! kotton-host-<rev>-linux-<arch>/
//!   relay/               the relay's tree, as above
//!   vault/               the vault's tree, as above
//!   install.sh           checks SHA256SUMS, runs relay/install.sh and vault/install.sh with a
//!                        key each and the address asked once, starts both, prints one line
//!   REVISION, LICENSE, NOTICES
//!   SHA256SUMS           every file above, the two trees' included
//! ```
//!
//! ## Where it builds
//!
//! In a target only this checkout writes, whatever `CARGO_TARGET_DIR` says (decision 0014):
//! the relay, a workspace of its own, under `out/release/relay`, and the vault, a package of
//! the workspace, under `out/release/workspace` beside the desktop's release
//! ([`target_of`]). The settings differential's tests build there too, so what the release
//! tested and what it packs are this tree's. `--no-build` packs what the last build put
//! there, and nothing from anywhere else.
//!
//! ## One target, and both binaries static
//!
//! Both are [`TARGET`], `x86_64-unknown-linux-musl`, and `release-server-test` refuses an
//! archive whose binary asks for a dynamic loader ([`static_or_refused`]): what a host runs
//! is the bytes the archive's sum names, and none of the host's own libraries.
//!
//! Measured 2026-09-26 on Ubuntu 24.04, rustc stable, `musl-tools` 1.2.4. The relay's C
//! libraries, `ring` and `aws-lc-sys`, build under `musl-gcc` as they are. The vault's
//! sqlcipher (`libsqlite3-sys`, `bundled-sqlcipher`, from `kotton-record`) links OpenSSL's
//! `libcrypto`, and a musl builder has none, so on musl alone `kvaultd` turns on
//! `bundled-sqlcipher-vendored-openssl`, which builds OpenSSL from source (`openssl-src`;
//! perl and make on the builder) and links it in. It is a target-specific dependency in
//! `core/kvaultd/Cargo.toml`, so every `-gnu` build — the desktop's included — links the
//! system's OpenSSL as it did, and `.cargo/config.toml` lifts `OPENSSL_NO_VENDOR` for the
//! musl target only.
//!
//! Until then the vault was released `-gnu`, taking glibc and `libcrypto.so.3` from the
//! host — the host's apt, not the release, named part of what ran.
//! `TASK-the-vault-cannot-be-released-static-because-sqlcipher-links-the-builders-libcrypto`.
//!
//! ## What a release does not carry, and says so
//!
//! Static trades the host's `apt upgrade` for the release: a fix in any C library a server
//! builds in — OpenSSL, SQLCipher, AWS-LC, `ring`'s — reaches a host only as a new release of
//! that server. So `release-server` prints, before anything else and whether or not it goes
//! on to build, every crate in the server's closure that compiles C ([`builds_c`], read with
//! `wx-check`'s reader along [`C_EDGES`]): each on [`C_WATCHED`] beside the newest crates.io
//! publishes, saying when they differ; each on [`C_NOT_WATCHED`] with its reason; and one on
//! neither as that ([`c_library_notice`]). It tells; it refuses nothing, and an index it cannot
//! reach is printed as that and not as "up to date". A test holds every C-building crate in
//! either server's closure to exactly one of the two lists.
//! `TASK-an-openssl-advisory-reaches-a-box-only-by-a-vault-release-and-nothing-notices-one`,
//! `TASK-a-released-server-carries-c-libraries-no-command-compares-with-their-newest`.
//!
//! ## What a release refuses
//!
//! As `release::box` did: a tree with changes git does not hold, untracked files included;
//! a `HEAD` that is not `origin/main`; and a commit already released — here, an archive of
//! that name already in `out/dist/`, whose sum it prints instead. An archive is written under a
//! staging name and renamed to its own only once `release-server-test` passes on it, so a
//! name in `out/dist/` is a release that was tested. `just clean` deletes `out/` and this
//! record of what was released with it; a person keeping one keeps the archive. `--not-a-release` builds from any tree,
//! names the archive `…-not-a-release-…`, and is how this is tested off `main`.
//!
//! And it refuses a tree whose installer it has not held to systemd's parser. Before
//! anything is read it refuses a machine without the parser (`systemds_parser_refusal`), an
//! early refusal of what the run below would refuse minutes later;
//! after the tree is held to origin/main, and before the build, it runs the settings
//! differential's four tests itself ([`SETTINGS_DIFFERENTIAL`]) and names no archive unless
//! libtest says `ok` of each by name. The proof is the release's own run at the commit it
//! packs, so no recorded result of an earlier run is anywhere for it to trust.
//! `--not-a-release` runs them as well.
//! `TASK-the-release-gate-requires-systemds-parser-and-does-not-run-the-differential`.

use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use crate::release::{self, Revision};

/// One server this releases.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Server {
    /// The word in the archive's name, the env file's name and the verb's argument.
    pub(crate) name: &'static str,
    /// The one executable.
    pub(crate) binary: &'static str,
    /// Where it is built from: a workspace package, or its own manifest.
    source: Source,
    /// The unit and the env file, in the tree.
    unit_src: &'static str,
    env_src: &'static str,
    /// The `[Service]` keys this unit says and the other does not, beside the ones both
    /// say in [`UNIT_KEYS`]. A key one unit needs is not a key the other may say
    /// (`TASK-the-normal-form-lets-the-relay-say-a-key-only-the-vault-needs`).
    own_service_keys: &'static [&'static str],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Source {
    Package(&'static str),
    Manifest(&'static str),
}

pub(crate) const RELAY: Server = Server {
    name: "relay",
    binary: "kotton-relay",
    source: Source::Manifest("infra/relay/Cargo.toml"),
    unit_src: "infra/relay/kotton-relay.service",
    env_src: "infra/relay/relay.env",
    own_service_keys: &[],
};

pub(crate) const VAULT: Server = Server {
    name: "vault",
    binary: "kvaultd",
    source: Source::Package("kvaultd"),
    unit_src: "infra/vault/kotton-vault.service",
    env_src: "infra/vault/vault.env",
    // The door's directory.
    own_service_keys: &["RuntimeDirectory", "RuntimeDirectoryMode"],
};

pub(crate) const SERVERS: [Server; 2] = [RELAY, VAULT];

/// The host's archive's word: the relay and the vault, for one machine.
pub(crate) const HOST: &str = "host";

/// The installer the host's archive carries as `install.sh`: it runs each tree's own.
const HOST_INSTALLER: &str = "infra/release/install-host.sh";

/// What `release-server` releases: one server, or the host, which is both.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Release {
    One(Server),
    Host,
}

impl Release {
    fn name(self) -> &'static str {
        match self {
            Release::One(s) => s.name,
            Release::Host => HOST,
        }
    }

    /// The servers it packs, the relay first.
    fn servers(self) -> Vec<Server> {
        match self {
            Release::One(s) => vec![s],
            Release::Host => SERVERS.to_vec(),
        }
    }
}

/// Every path the host's archive holds under its top directory, sorted: each server's
/// [`Server::entries`] under a directory of its name, and the host's own files beside them.
pub(crate) fn host_entries() -> Vec<String> {
    let mut v = vec![release::ARCHIVE_INSTALLER.to_string(), "REVISION".to_string(), "SHA256SUMS".to_string()];
    v.extend(release::OWN.iter().map(|f| f.to_string()));
    for s in SERVERS {
        v.extend(s.entries().into_iter().map(|e| format!("{}/{e}", s.name)));
    }
    v.sort();
    v
}

/// The one target both servers are released for: static, so a host supplies no library
/// of what runs. `--target` names another, and the test still refuses anything that is not
/// static; a vault for another musl target also needs that target's
/// `<TARGET>_OPENSSL_NO_VENDOR = "0"` in `.cargo/config.toml`, which only this one has.
pub(crate) const TARGET: &str = "x86_64-unknown-linux-musl";

/// The installer every server archive carries as `install.sh`.
const INSTALLER: &str = "infra/release/install-server.sh";

impl Server {
    /// The unit as the tree holds it, held to [`unit_normal_form`] first — the one form
    /// [`unit_value`] is exact on.
    pub(crate) fn unit_text(&self, workspace_root: &Path) -> Result<String, String> {
        let path = workspace_root.join(self.unit_src);
        let text = std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", self.unit_src))?;
        unit_normal_form(&text, self.own_service_keys).map_err(|e| format!("{}: {e}", self.unit_src))?;
        Ok(text)
    }

    pub(crate) fn unit_src(&self) -> &'static str {
        self.unit_src
    }

    /// The `cargo` arguments that select what this server is built from: its package in the
    /// workspace, or its own workspace by manifest path.
    pub(crate) fn selector(&self) -> [&'static str; 2] {
        match self.source {
            Source::Package(p) => ["-p", p],
            Source::Manifest(m) => ["--manifest-path", m],
        }
    }

    /// The lockfile this server resolves from: the workspace's, or the one beside its own
    /// manifest.
    pub(crate) fn lockfile(&self) -> PathBuf {
        match self.source {
            Source::Package(_) => PathBuf::from("Cargo.lock"),
            Source::Manifest(m) => Path::new(m).with_file_name("Cargo.lock"),
        }
    }

    pub(crate) fn unit(&self) -> String {
        format!("kotton-{}.service", self.name)
    }

    pub(crate) fn env(&self) -> String {
        format!("{}.env", self.name)
    }

    /// The env file's mode after an install as root: the vault's is its user's group's to
    /// read, because `kvaultd`'s verbs read it as that user too; the relay's is root's alone.
    pub(crate) fn env_mode(&self) -> u32 {
        if self.name == "vault" {
            0o640
        } else {
            0o600
        }
    }

    /// `x86_64` of `x86_64-unknown-linux-musl`: the archive's architecture.
    fn arch(target: &str) -> &str {
        target.split('-').next().unwrap_or(target)
    }

    /// Every path the archive holds under its top directory, sorted.
    pub(crate) fn entries(&self) -> Vec<String> {
        let mut v = vec![
            format!("bin/{}", self.binary),
            self.unit(),
            self.env(),
            release::ARCHIVE_INSTALLER.to_string(),
            "REVISION".to_string(),
            crate::license_check::FILE.to_string(),
            "SHA256SUMS".to_string(),
        ];
        v.extend(release::OWN.iter().map(|f| f.to_string()));
        v.sort();
        v
    }

    /// Which server an archive is, from its name.
    fn of_archive(archive: &Path) -> Option<Server> {
        let file = archive.file_name()?.to_str()?;
        SERVERS
            .into_iter()
            .find(|s| file.starts_with(&format!("kotton-{}-", s.name)))
    }
}

/// The archive's top directory and file stem, for a server's `name` or [`HOST`].
pub(crate) fn archive_name(name: &str, rev: &str, released: bool, target: &str) -> String {
    format!(
        "kotton-{}-{}{}-linux-{}",
        name,
        rev,
        if released { "" } else { "-not-a-release" },
        Server::arch(target)
    )
}

/// Why this commit may not be released from this tree, if it may not.
///
/// `release::box` refused the same three, in this order; the third was a tag in a
/// registry, and is an archive in `out/dist/` here — this machine's record of what it released.
pub(crate) fn refusal(rev: &Revision, origin_main: Option<&str>, head: &str, released_at: &Path) -> Option<String> {
    match origin_main {
        None => return Some("cannot read origin/main — `git fetch origin main` failed, and a release is built from main as origin has it".into()),
        Some(main) if main != head => {
            return Some(format!(
                "HEAD is {}, origin/main is {} — a release is built from main as origin has it\n  git switch main && git pull --ff-only   (and push first, if main is ahead)",
                &head[..head.len().min(12)],
                &main[..main.len().min(12)]
            ))
        }
        Some(_) => {}
    }
    if rev.dirty {
        return Some(format!(
            "the tree has changes git does not hold, so the archive would not be {}",
            rev.sha
        ));
    }
    if released_at.exists() {
        return Some(format!(
            "{} exists: {} is already released, and a commit is released once — a second build is other bytes under the same name. Its sum:\n  {}  {}\nThe next commit on main releases cleanly.",
            released_at.display(),
            rev.sha,
            release::sha256(released_at).unwrap_or_else(|| "(no sha256sum or shasum on this machine)".into()),
            released_at.file_name().and_then(|f| f.to_str()).unwrap_or("")
        ));
    }
    None
}

fn git(workspace_root: &Path, args: &[&str]) -> Option<String> {
    Command::new("git")
        .args(args)
        .current_dir(workspace_root)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
}

pub fn release_server(workspace_root: &Path, args: &[String]) {
    let not_a_release = args.iter().any(|a| a == "--not-a-release");
    let no_build = args.iter().any(|a| a == "--no-build");
    let target_arg = args
        .iter()
        .position(|a| a == "--target")
        .and_then(|i| args.get(i + 1).cloned());
    let positional: Vec<&String> = args
        .iter()
        .enumerate()
        .filter(|(i, a)| !a.starts_with("--") && (*i == 0 || args[i - 1] != "--target"))
        .map(|(_, a)| a)
        .collect();
    let what = match positional.as_slice() {
        [n] if n.as_str() == HOST => Release::Host,
        [n] => match SERVERS.iter().find(|s| s.name == n.as_str()) {
            Some(s) => Release::One(*s),
            None => usage(),
        },
        _ => usage(),
    };
    let target = target_arg.unwrap_or_else(|| TARGET.to_string());
    // First, before anything is read, fetched or built: a release is cut only where the
    // settings differential can be held to systemd's parser. The differential's run below is
    // the requirement and refuses this machine too; what this guards that the run does not is
    // the minutes before it — a fetch and two crates' tests compiled — and the run's own
    // failure, written for a developer, which says to set the declaration this verb ignores.
    // Held by `release_server_refuses_where_systemds_parser_is_absent`
    // (`TASK-the-release-gates-parser-presence-refusals-guard-what-the-differentials-run-now-proves`).
    if let Some(why) = systemds_parser_refusal(systemds_parser::find()) {
        eprintln!("release-server: {why}\n  nothing was built.");
        std::process::exit(1);
    }

    let rev = release::revision(workspace_root);
    let dist = crate::out::dist();
    let name = archive_name(what.name(), &rev.sha, !not_a_release, &target);
    let archive = dist.join(format!("{name}{}", release::PACKED));

    // Read out of the closure for this target, so a -gnu vault, which links the system's
    // libcrypto, is not told about an openssl-src it does not build.
    for server in what.servers() {
        println!("{}", c_library_notice(workspace_root, &server, &target));
    }

    if not_a_release {
        println!("release-server: --not-a-release — {name} is built from this tree, whatever it holds, and is no release");
    } else {
        let _ = git(workspace_root, &["fetch", "--quiet", "origin", "main"]);
        let head = git(workspace_root, &["rev-parse", "HEAD"]).unwrap_or_default();
        let main = git(workspace_root, &["rev-parse", "origin/main"]);
        if let Some(why) = refusal(&rev, main.as_deref(), &head, &archive) {
            eprintln!("release-server: {why}");
            if rev.dirty {
                let _ = Command::new("git")
                    .args(["status", "--short"])
                    .current_dir(workspace_root)
                    .status();
            }
            eprintln!("  nothing was built.");
            std::process::exit(1);
        }
    }

    // At the tree it is about to build, which for a release the refusal above has just held to
    // origin/main with nothing git does not hold: the four tests that hold the installer's
    // reading of a settings file to systemd's own, run here, by name. `--not-a-release` runs
    // them too, so the rehearsal is the verb and not a shorter one.
    match settings_differential(workspace_root) {
        Ok(()) => println!(
            "release-server: the settings differential compared against systemd's parser at {}: {}",
            rev.sha,
            SETTINGS_DIFFERENTIAL.iter().flat_map(|(_, _, n)| n.iter().copied()).collect::<Vec<_>>().join(", ")
        ),
        Err(wrong) => {
            eprintln!(
                "release-server: the settings differential did not compare against systemd's parser at {}:\n  {}\n  an archive is named only where install.sh's reading of a settings file was held to systemd's, at the tree it is built from\n  nothing was built.",
                rev.sha,
                wrong.join("\n  ")
            );
            std::process::exit(1);
        }
    }

    if !no_build {
        for server in what.servers() {
            build(workspace_root, &server, &target);
        }
    }

    let packed = match what {
        Release::One(server) => pack(workspace_root, &dist, &server, &rev, !not_a_release, &target, &name),
        Release::Host => pack_host(workspace_root, &dist, &rev, !not_a_release, &target, &name),
    };
    let staged = packed.unwrap_or_else(|e| {
        eprintln!("release-server: {e}");
        std::process::exit(1);
    });

    println!("\nrelease-server: testing the archive it just made, installed into a clean directory");
    let relay = match what {
        Release::One(server) if server.name == VAULT.name => {
            Some(relay_for_vault_test(&dist, &rev.sha, Server::arch(&target), !not_a_release).unwrap_or_else(|e| {
                eprintln!("release-server: {e}");
                std::process::exit(1);
            }))
        }
        _ => None,
    };
    let tested = match what {
        Release::One(server) => server_test(&staged, &server, relay.as_deref()),
        Release::Host => host_test(&staged),
    };
    if let Err(e) = tested {
        eprintln!(
            "release-server: {} failed its install test, and is not named:\n  {e}",
            staged.display()
        );
        std::process::exit(1);
    }
    std::fs::rename(&staged, &archive).unwrap_or_else(|e| {
        eprintln!("release-server: cannot name {}: {e}", archive.display());
        std::process::exit(1);
    });

    let digest = release::sha256(&archive).unwrap_or_else(|| {
        eprintln!("release-server: no sha256sum or shasum on this machine, so the archive has no sum to print");
        std::process::exit(1);
    });
    println!("\nrelease-server: {} passed its install test", archive.display());
    println!("{digest}  {name}.tar.gz");
}

/// Where "newest published" is read: crates.io's sparse index, the one `cargo update` reads.
const CRATES_INDEX: &str = "https://index.crates.io";

/// What `release-server` says about the C a server builds in, before anything else and
/// whether or not it goes on to build: each crate in its closure that compiles C
/// ([`builds_c`]), compared with the newest crates.io publishes when it is on [`C_WATCHED`],
/// named with its reason when it is on [`C_NOT_WATCHED`], and said as neither when it is on
/// neither. It tells; it refuses nothing — a closure or an index it could not read is printed
/// as that, never as "up to date".
fn c_library_notice(workspace_root: &Path, server: &Server, target: &str) -> String {
    let at = utc_minute();
    let found = crate::wx_check::closure(workspace_root, server, target, C_EDGES).and_then(|tree| {
        let lock = server.lockfile();
        std::fs::read_to_string(workspace_root.join(&lock))
            .map(|l| builds_c(&tree, &l))
            .map_err(|e| format!("{}: {e}", lock.display()))
    });
    c_library_report(server, target, &at, found, fetch_index)
}

/// The notice itself, from the crates found (or why there are none) and a way to read a
/// crate's index file — `curl` in [`c_library_notice`], a table in the tests.
fn c_library_report(
    server: &Server,
    target: &str,
    at: &str,
    found: Result<Vec<(String, String)>, String>,
    index: impl Fn(&str) -> Result<String, String>,
) -> String {
    let mut out = vec![
        format!(
            "release-server: {} builds C in; a fix in it reaches a host only as a new {} release",
            server.binary, server.name
        ),
        format!(
            "  read from `cargo tree {} -e {C_EDGES} --target {target}`: every crate {} says depends on cc or cmake",
            server.selector().join(" "),
            server.lockfile().display()
        ),
        format!("  compared with crates.io's index ({CRATES_INDEX}), {at}; yanked and pre-release versions are not \"published\""),
    ];
    let found = match found {
        Ok(f) => f,
        Err(why) => {
            out.push(format!("  the closure could not be read ({why}) — nothing compared; this is not \"up to date\""));
            return out.join("\n");
        }
    };
    for (name, version) in found {
        if let Some((_, carries)) = C_WATCHED.iter().find(|(n, _)| *n == name) {
            out.push(format!("  {name} {version} — {carries}"));
            let text = index(&name);
            out.extend(c_comparison(&name, &version, server.name, text.as_deref().map_err(String::as_str)));
        } else if let Some((_, why)) = C_NOT_WATCHED.iter().find(|(n, _)| *n == name) {
            out.push(format!("  {name} {version} — not watched: {why}"));
        } else {
            out.push(format!(
                "  {name} {version} — UNWATCHED AND UNNAMED: it builds C and is on neither C_WATCHED nor C_NOT_WATCHED in xtask/src/release_server.rs; not compared"
            ));
        }
    }
    out.join("\n")
}

/// `name`'s file in the sparse index, by the index's own layout.
fn index_url(name: &str) -> String {
    let n = name.to_ascii_lowercase();
    let dir = match n.len() {
        1 => "1".to_string(),
        2 => "2".to_string(),
        3 => format!("3/{}", &n[..1]),
        _ => format!("{}/{}", &n[..2], &n[2..4]),
    };
    format!("{CRATES_INDEX}/{dir}/{n}")
}

/// `name`'s index file, asked with `curl`, or why it could not be read.
fn fetch_index(name: &str) -> Result<String, String> {
    let url = index_url(name);
    let o = Command::new("curl")
        .args(["-sS", "--fail", "--max-time", "20", &url])
        .output()
        .map_err(|e| format!("{url}: curl: {e}"))?;
    if o.status.success() {
        Ok(String::from_utf8_lossy(&o.stdout).into_owned())
    } else {
        Err(format!("{url}: {}", String::from_utf8_lossy(&o.stderr).trim()))
    }
}

/// Now, to the minute, in UTC: when the index was asked.
fn utc_minute() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("{}T{:02}:{:02}Z", crate::today(), secs % 86_400 / 3600, secs % 3600 / 60)
}

/// One watched crate's comparison, from the version the closure holds and the index's text
/// (or why there is none).
///
/// Prints the newest published, and says which of two kinds of newer there is: one in the
/// locked version's semver-compatible range ([`compatible`]), which `cargo update -p <name>`
/// reaches, and one past it, which arrives only when what depends on the crate asks for it.
pub(crate) fn c_comparison(name: &str, locked: &str, server: &str, index: Result<&str, &str>) -> Vec<String> {
    let mut out = Vec::new();
    let unknown = |out: &mut Vec<String>, why: String| {
        out.push(format!("    newest published:  unknown — {why}"));
        out.push("    not compared; this is not \"up to date\"".to_string());
    };
    let index = match index {
        Ok(text) => text,
        Err(why) => {
            unknown(&mut out, format!("the index could not be read ({why})"));
            return out;
        }
    };
    let Some(locked_core) = semver_core(locked) else {
        out.push(format!("    {locked} is not a version this can compare"));
        return out;
    };
    let published: Vec<((u64, u64, u64), String)> = index
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .filter(|v| v["yanked"].as_bool() != Some(true))
        .filter_map(|v| v["vers"].as_str().map(str::to_string))
        .filter_map(|vers| Some((semver_core(&vers)?, vers)))
        .collect();
    let Some(newest) = published.iter().max_by_key(|p| p.0) else {
        unknown(&mut out, format!("{} listed no version", index_url(name)));
        return out;
    };
    out.push(format!("    newest published:  {}", newest.1));
    let (range, label) = compatible(locked_core);
    let same = published.iter().filter(|p| compatible(p.0).0 == range).max_by_key(|p| p.0);
    let past = (newest.0 > locked_core && compatible(newest.0).0 != range).then_some(newest);
    let crosses = format!(
        "which `cargo update -p {name}` does not cross; it arrives when what depends on it takes it (`cargo tree -i {name}`)"
    );
    match same.filter(|p| p.0 > locked_core) {
        Some(same) => {
            out.push(format!("    DIFFERS: {} is published in {label} — `cargo update -p {name}`, then release the {server}", same.1));
            if let Some(past) = past {
                out.push(format!("    and {} is past {label}, {crosses}", past.1));
            }
        }
        None => match past {
            Some(past) => out.push(format!("    DIFFERS: {} is past {label}, the newest of which is the locked one, {crosses}", past.1)),
            None => out.push("    the locked version is the newest published".to_string()),
        },
    }
    out
}

/// The semver-compatible range a version sits in — the one `cargo update -p` moves within —
/// as a key and a label: `300.x` for `300.6.1`, `0.28.x` for `0.28.0`, `0.0.3` for `0.0.3`.
fn compatible(v: (u64, u64, u64)) -> ((u64, u64, u64), String) {
    match v {
        (major, _, _) if major != 0 => ((major, 0, 0), format!("{major}.x")),
        (0, minor, _) if minor != 0 => ((0, minor, 0), format!("0.{minor}.x")),
        (_, _, patch) => ((0, 0, patch), format!("0.0.{patch}")),
    }
}

/// `300.6.1` of `300.6.1+3.6.3`; `None` for anything not three numbers — a pre-release's
/// `0-rc1` is not one.
fn semver_core(vers: &str) -> Option<(u64, u64, u64)> {
    let core = vers.split('+').next()?;
    let mut n = core.split('.').map(|p| p.parse::<u64>().ok());
    let v = (n.next()??, n.next()??, n.next()??);
    n.next().is_none().then_some(v)
}

/// The edges a server's C is read along: build edges as well as normal ones, because a
/// `-sys` crate's library is often a build-dependency's — `openssl-src` is `openssl-sys`'s.
/// It reads the builder's tools too (`cmake`), which is why [`C_NOT_WATCHED`] names them.
pub(crate) const C_EDGES: &str = "normal,build,no-proc-macro";

/// Crates that build an upstream C library into a server, each with the library it carries.
/// `release-server` compares each one in the server's closure with the newest crates.io
/// publishes.
pub(crate) const C_WATCHED: &[(&str, &str)] = &[
    ("openssl-src", "OpenSSL, built from source into the vault on musl"),
    ("libsqlite3-sys", "SQLCipher and the SQLite it carries, bundled"),
    ("aws-lc-sys", "AWS-LC"),
    ("ring", "ring's C and assembly, derived from BoringSSL"),
];

/// Crates in a server's closure that depend on `cc` or `cmake` and are deliberately not
/// compared, each with the reason. Named here rather than excluded by a rule: no rule the
/// lockfile can evaluate tells an upstream library from a crate's own C, and a reason a
/// reviewer can read is the claim held.
pub(crate) const C_NOT_WATCHED: &[(&str, &str)] = &[
    (
        "blake3",
        "its C is its own SIMD code, not an upstream library, versioned and fixed with the crate like any Rust dependency",
    ),
    (
        "openssl-sys",
        "compiles nothing in: without its bindgen, aws-lc or boringssl features its build script calls cc only to \
         preprocess OpenSSL's headers, and the OpenSSL it links is openssl-src's, which is watched",
    ),
    ("cmake", "a build tool run on the builder to drive a C build (aws-lc-sys's); nothing of it is linked"),
];

/// Every crate in `tree` (a `cargo tree --prefix none` listing) whose entry in `lock`
/// depends on `cc` or `cmake` — the crates whose build compiles C — as `(name, version)`,
/// once each, in the tree's order.
pub(crate) fn builds_c(tree: &str, lock: &str) -> Vec<(String, String)> {
    let compiles: Vec<(String, String)> = lock
        .split("[[package]]")
        .filter_map(|block| {
            let field = |key: &str| {
                block.lines().find_map(|l| {
                    l.trim().strip_prefix(key).and_then(|v| v.strip_prefix(" = \"")).and_then(|v| v.strip_suffix('"')).map(str::to_string)
                })
            };
            let deps = block.split_once("dependencies = [")?.1.split(']').next()?;
            deps.lines()
                .map(|l| l.trim().trim_end_matches(',').trim_matches('"'))
                .any(|d| ["cc", "cmake"].contains(&d.split(' ').next().unwrap_or("")))
                .then(|| Some((field("name")?, field("version")?)))?
        })
        .collect();
    let mut found: Vec<(String, String)> = Vec::new();
    for line in tree.lines() {
        let mut words = line.split_whitespace();
        let (Some(name), Some(v)) = (words.next(), words.next()) else { continue };
        let entry = (name.to_string(), v.trim_start_matches('v').to_string());
        if compiles.contains(&entry) && !found.contains(&entry) {
            found.push(entry);
        }
    }
    found
}

fn usage() -> ! {
    eprintln!("usage: cargo xtask release-server relay|vault|host [--not-a-release] [--no-build] [--target <triple>]");
    std::process::exit(2)
}

/// The relay the vault's test points at: the relay archive of the same commit and
/// architecture beside it, or the newest relay archive there. A vault is released on its
/// own cadence, so any relay that passed its own test will do; which one is printed.
///
/// For a release, only a released relay will do: a `-not-a-release` archive was never
/// held to `main`, and a release's test does not stand on one.
fn relay_for_vault_test(dist: &Path, rev: &str, arch: &str, released_only: bool) -> Result<PathBuf, String> {
    let mut candidates: Vec<(std::time::SystemTime, PathBuf)> = std::fs::read_dir(dist)
        .map_err(|e| format!("cannot read {}: {e}", dist.display()))?
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|f| f.to_str())
                .is_some_and(|f| {
                    f.starts_with("kotton-relay-")
                        && f.ends_with(&format!("-linux-{arch}.tar.gz"))
                        && !(released_only && f.contains("-not-a-release-"))
                })
        })
        .filter_map(|p| Some((p.metadata().ok()?.modified().ok()?, p)))
        .collect();
    if let Some((_, same)) = candidates.iter().find(|(_, p)| {
        p.file_name()
            .and_then(|f| f.to_str())
            .is_some_and(|f| f.starts_with(&format!("kotton-relay-{rev}")))
    }) {
        return Ok(same.clone());
    }
    candidates.sort();
    candidates.pop().map(|(_, p)| p).ok_or_else(|| {
        format!(
            "the vault's test runs it against a relay, and there is no kotton-relay-*-linux-{arch}.tar.gz in {} — cargo xtask release-server relay first",
            dist.display()
        )
    })
}

/// Where a server, or the tests of what it is built from, build for a release: a private
/// target of this checkout's, never `CARGO_TARGET_DIR` — the relay's own
/// `out/release/relay`, and the workspace's `out/release/workspace`, which the vault shares
/// with the desktop's release (`release::workspace_target`).
pub(crate) fn target_of(server: &Server) -> PathBuf {
    source_target(server.source)
}

fn source_target(source: Source) -> PathBuf {
    match source {
        Source::Package(_) => release::workspace_target(),
        Source::Manifest(_) => crate::out::private_target(release::RELAY),
    }
}

/// The release build of `server` for `target`, into [`target_of`] — handed to cargo as
/// `--target-dir`, so `built_binary` knows where it is by construction.
pub(crate) fn build_command(workspace_root: &Path, server: &Server, target: &str) -> Command {
    let mut cargo = Command::new("cargo");
    cargo.args(["build", "--release", "--locked", "--target", target]);
    match server.source {
        Source::Package(p) => cargo.args(["-p", p, "--bin", server.binary]),
        Source::Manifest(m) => cargo.args(["--manifest-path", m, "--bin", server.binary]),
    };
    cargo.arg("--target-dir").arg(target_of(server)).current_dir(workspace_root);
    cargo
}

fn build(workspace_root: &Path, server: &Server, target: &str) {
    let status = build_command(workspace_root, server, target).status().unwrap_or_else(|e| {
        eprintln!("release-server: could not start cargo: {e}");
        std::process::exit(1);
    });
    if !status.success() {
        eprintln!("release-server: cargo build --release --target {target} failed");
        if target.ends_with("-musl") {
            eprintln!("  a -musl build needs the target (rustup target add {target}), a musl C compiler (musl-tools), and perl and make for the vault's OpenSSL");
            eprintln!("  cargo xtask doctor --tier server checks this machine for each, and prints what to install");
        }
        std::process::exit(1);
    }
}

/// Where cargo put the binary: the private target `build` handed cargo ([`target_of`]).
/// Never the workspace's target as `cargo metadata` reports it, which is `CARGO_TARGET_DIR`
/// when that is exported, and never a directory composed from the default layout.
fn built_binary(server: &Server, target: &str) -> PathBuf {
    target_of(server).join(target).join("release").join(server.binary)
}

/// The binary a pack lays out, where `build` left it — or, before anything else a pack reads,
/// the act that builds it: `--no-build` with nothing built stops here, not at whatever a later
/// step (the notices' licence read) happens to find first.
fn binary_to_pack(server: &Server, target: &str) -> Result<PathBuf, String> {
    let binary = built_binary(server, target);
    if binary.is_file() {
        return Ok(binary);
    }
    Err(format!(
        "{} is not built at {}\n  build it: cargo xtask release-server {} (without --no-build)",
        server.binary,
        binary.display(),
        server.name
    ))
}

/// Lay the tree out under `out/dist/<name>/` and pack it under a staging name.
fn pack(
    workspace_root: &Path,
    dist: &Path,
    server: &Server,
    rev: &Revision,
    released: bool,
    target: &str,
    name: &str,
) -> Result<PathBuf, String> {
    let binary = binary_to_pack(server, target)?;
    let root = fresh_dir(&dist.join(name))?;
    let notices = server_notices(workspace_root, server, name, target)?;
    lay_out(workspace_root, server, &binary, &revision_text(rev, released, target), &notices, &root)?;
    tar_staged(dist, name)
}

/// The host's archive: each server's tree laid out as its own archive's is, under a directory
/// of its name, beside the host's installer, `REVISION`, Kotton's own notes and `SHA256SUMS`
/// over every file ([`host_entries`]), packed under a staging name.
fn pack_host(workspace_root: &Path, dist: &Path, rev: &Revision, released: bool, target: &str, name: &str) -> Result<PathBuf, String> {
    let binaries = SERVERS.iter().map(|s| binary_to_pack(s, target)).collect::<Result<Vec<_>, _>>()?;
    let root = fresh_dir(&dist.join(name))?;
    let revision = revision_text(rev, released, target);
    let mut notices = Vec::new();
    for (server, binary) in SERVERS.into_iter().zip(binaries) {
        notices.push((server, binary, server_notices(workspace_root, &server, name, target)?));
    }
    let laid: Vec<(Server, &Path, &str)> = notices.iter().map(|(s, b, n)| (*s, b.as_path(), n.as_str())).collect();
    lay_out_host(workspace_root, &laid, &revision, &root)?;
    tar_staged(dist, name)
}

/// `dir`, emptied: what a pack lays out is only what it writes.
fn fresh_dir(dir: &Path) -> Result<PathBuf, String> {
    if dir.exists() {
        std::fs::remove_dir_all(dir).map_err(|e| format!("cannot clear {}: {e}", dir.display()))?;
    }
    std::fs::create_dir_all(dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    Ok(dir.to_path_buf())
}

/// What `REVISION` says: the commit, whether it is a release, and the target it was built for.
fn revision_text(rev: &Revision, released: bool, target: &str) -> String {
    format!(
        "{}{}\nbuilt for {target}\n",
        rev.sha,
        if released { "" } else { " (not a release: built with --not-a-release)" }
    )
}

/// `server`'s `THIRD-PARTY-NOTICES`, for the archive `name`. Built for `target`, so resolved
/// for it: `--target` may name another than [`TARGET`].
fn server_notices(workspace_root: &Path, server: &Server, name: &str, target: &str) -> Result<String, String> {
    let shipped = match server.name {
        "relay" => crate::license_check::RELAY,
        _ => crate::license_check::VAULT,
    };
    crate::license_check::notices(workspace_root, &shipped, name, Some(target))
}

/// Lay `server`'s tree out in `root`, which exists: `binary` as its one executable, its unit,
/// its env file, the server installer, `REVISION`, `notices`, Kotton's own notes, and
/// `SHA256SUMS` over every one of them ([`Server::entries`]).
fn lay_out(workspace_root: &Path, server: &Server, binary: &Path, revision: &str, notices: &str, root: &Path) -> Result<(), String> {
    std::fs::create_dir_all(root.join("bin")).map_err(|e| format!("cannot create {}: {e}", root.display()))?;
    release::copy(binary, &root.join("bin").join(server.binary))
        .map_err(|e| format!("{e}\n  build it: cargo xtask release-server {} (without --no-build)", server.name))?;
    release::copy(&workspace_root.join(server.unit_src), &root.join(server.unit()))?;
    release::copy(&workspace_root.join(server.env_src), &root.join(server.env()))?;
    release::copy(&workspace_root.join(INSTALLER), &root.join(release::ARCHIVE_INSTALLER))?;
    for f in release::OWN {
        release::copy(&workspace_root.join(f), &root.join(f))?;
    }
    std::fs::write(root.join("REVISION"), revision).map_err(|e| format!("cannot write REVISION: {e}"))?;
    std::fs::write(root.join(crate::license_check::FILE), notices)
        .map_err(|e| format!("cannot write {}: {e}", crate::license_check::FILE))?;
    // The sums, over every file but themselves, in the form `sha256sum -c` reads.
    let summed: Vec<String> = server.entries().into_iter().filter(|e| e != "SHA256SUMS").collect();
    let sums = sum_lines(root, &summed)?;
    std::fs::write(root.join("SHA256SUMS"), sums).map_err(|e| format!("cannot write SHA256SUMS: {e}"))
}

/// Lay the host's tree out in `root`, which exists: each of `servers` — with the binary and
/// the notices its tree carries — by [`lay_out`] under a directory of its name, then the host's
/// installer, `REVISION`, Kotton's own notes and `SHA256SUMS` over every file but itself.
fn lay_out_host(workspace_root: &Path, servers: &[(Server, &Path, &str)], revision: &str, root: &Path) -> Result<(), String> {
    for (server, binary, notices) in servers {
        lay_out(workspace_root, server, binary, revision, notices, &root.join(server.name))?;
    }
    release::copy(&workspace_root.join(HOST_INSTALLER), &root.join(release::ARCHIVE_INSTALLER))?;
    for f in release::OWN {
        release::copy(&workspace_root.join(f), &root.join(f))?;
    }
    std::fs::write(root.join("REVISION"), revision).map_err(|e| format!("cannot write REVISION: {e}"))?;
    let summed: Vec<String> = host_entries().into_iter().filter(|e| e != "SHA256SUMS").collect();
    let sums = sum_lines(root, &summed)?;
    std::fs::write(root.join("SHA256SUMS"), sums).map_err(|e| format!("cannot write SHA256SUMS: {e}"))
}

/// Pack `dist/<name>/` as `<name>.tar.gz.untested` beside where it will be named: renamed only
/// when the test passes.
fn tar_staged(dist: &Path, name: &str) -> Result<PathBuf, String> {
    let root = dist.join(name);
    let staged = dist.join(format!("{name}{}.untested", release::PACKED));
    let _ = std::fs::remove_file(&staged);
    let status = Command::new("tar")
        .arg("-czf")
        .arg(&staged)
        .arg("-C")
        .arg(dist)
        .arg(name)
        .status()
        .map_err(|e| format!("cannot run tar: {e}"))?;
    if !status.success() {
        return Err(format!("tar could not pack {}", root.display()));
    }
    println!("release-server: packed {}", staged.display());
    Ok(staged)
}

/// `sha256sum`'s lines for `files`, relative to `dir`.
fn sum_lines(dir: &Path, files: &[String]) -> Result<String, String> {
    let mut out = String::new();
    for f in files {
        let digest = release::sha256(&dir.join(f)).ok_or("no sha256sum or shasum on this machine")?;
        out.push_str(&format!("{digest}  {f}\n"));
    }
    Ok(out)
}

pub fn release_server_test(args: &[String]) {
    let relay_arg = args
        .iter()
        .position(|a| a == "--relay")
        .and_then(|i| args.get(i + 1).cloned());
    let Some(archive) = args
        .iter()
        .enumerate()
        .find(|(i, a)| !a.starts_with("--") && (*i == 0 || args[i - 1] != "--relay"))
        .map(|(_, a)| a.clone())
    else {
        eprintln!("usage: cargo xtask release-server-test <out/dist/kotton-relay-….tar.gz | out/dist/kotton-vault-….tar.gz | out/dist/kotton-host-….tar.gz> [--relay <relay archive>]");
        std::process::exit(2);
    };
    let archive = PathBuf::from(archive);
    if archive.file_name().and_then(|f| f.to_str()).is_some_and(|f| f.starts_with(&format!("kotton-{HOST}-"))) {
        match host_test(&archive) {
            Ok(()) => println!("release-server-test: PASS — {}", archive.display()),
            Err(e) => {
                eprintln!("release-server-test: FAIL — {}\n  {e}", archive.display());
                std::process::exit(1);
            }
        }
        return;
    }
    // No parser check here: this verb installs an archive and starts it, and compares nothing
    // with systemd's parser. The archive it tests was named only by `release-server`, which ran
    // the differential. Held by `release_server_test_does_not_ask_for_systemds_parser`
    // (`TASK-the-release-gates-parser-presence-refusals-guard-what-the-differentials-run-now-proves`).
    let Some(server) = Server::of_archive(&archive) else {
        eprintln!("release-server-test: {} is named none of kotton-relay-…, kotton-vault-… and kotton-host-…", archive.display());
        std::process::exit(2);
    };
    let relay = match (server.name, relay_arg) {
        ("vault", Some(r)) => Some(PathBuf::from(r)),
        ("vault", None) => {
            let dir = archive.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
            let file = archive.file_name().and_then(|f| f.to_str()).unwrap_or("");
            let rev: String = file.trim_start_matches("kotton-vault-").chars().take(12).collect();
            let arch = file
                .trim_end_matches(".tar.gz")
                .rsplit("-linux-")
                .next()
                .unwrap_or("");
            match relay_for_vault_test(dir, &rev, arch, !file.contains("-not-a-release-")) {
                Ok(r) => Some(r),
                Err(e) => {
                    eprintln!("release-server-test: {e}\n  or name one: --relay <archive>");
                    std::process::exit(2);
                }
            }
        }
        _ => None,
    };
    match server_test(&archive, &server, relay.as_deref()) {
        Ok(()) => println!("release-server-test: PASS — {}", archive.display()),
        Err(e) => {
            eprintln!("release-server-test: FAIL — {}\n  {e}", archive.display());
            std::process::exit(1);
        }
    }
}

/// Install `archive` into a clean root and start its binary from there.
///
/// In order, each a process of its own, with an environment of `PATH` (the system
/// directories only, and for step 3 the [`StandInSystem`] commands ahead of them) and what
/// the step names:
///
/// 1. lists the archive and refuses any file the layout does not name, and any entry
///    that is not a plain file or a directory;
/// 2. unpacks it, runs `sha256sum -c SHA256SUMS` in the unpacked directory, and holds its
///    `THIRD-PARTY-NOTICES` to that file's shape (`license_check::check_notices`);
/// 3. runs `install.sh` with `KOTTON_ROOT` under a fresh directory and the operator's
///    key, and checks it placed the binary, the unit and the env file where the unit
///    names them, and ran `create` as the service's user ([`created_as_its_user`]). It
///    runs as from an ssh session (`SSH_CONNECTION` set) with no terminal: each must print
///    the `KOTTON_PUBLIC_ADDR=<address> sh …/install.sh` line to run, and leave its
///    address empty in the settings it wrote;
/// 4. refuses a binary that is not static ([`static_or_refused`]): it needs nothing of
///    the host;
/// 5. the relay: runs the installed `kotton-relay` with the installed env file, bound
///    to a free loopback port, and reads `/health`. The vault: installs and starts the
///    relay archive the same way, then runs the installed `kvaultd` with the installed
///    env file and `KOTTON_BASE_DIR` under the root — standing at no relay, since
///    nothing but its owner's desktop tells a vault where to stand — and reads its
///    first log line; it must still be running a second later;
/// 6. installs the archive once more into another fresh directory, given
///    `KOTTON_PUBLIC_ADDR` ([`install_addressed`]), and holds the line it ends on to name
///    that address.
///
/// Run as root, every step runs the service as one uid of its own — a number no user or
/// group of this machine has. In steps 3 and 6 it is the user install.sh makes
/// ([`StandInSystem`]), so `create` runs as it, through `setpriv`, on a state directory it
/// owns, before anything here touches the directory. Step 5 runs each installed binary as
/// it, entered with `setpriv`, its directories made its own as the unit's
/// `StateDirectory=` and `RuntimeDirectory=` make them — and then the verbs at the host's
/// shell as the unit files say to type them: `kvaultd tenants` as root, against
/// the door the vault made as its own user, and `kotton-relay operator enrol` as the
/// relay's user. Run as anyone else, both run as that user, and the test says so.
///
/// It does not run systemd: the unit is placed and read, not started, and install.sh's
/// user is made in a stand-in for the user database ([`StandInSystem`]), not on this machine.
pub(crate) fn server_test(archive: &Path, server: &Server, relay: Option<&Path>) -> Result<(), String> {
    let archive = archive
        .canonicalize()
        .map_err(|e| format!("cannot read {}: {e}", archive.display()))?;
    // Beside the archive, not under the system temp directory: a base directory there
    // is a throwaway root to the vault, which then keeps its secrets in memory, and the
    // host's KOTTON_SECRETS=file path would go untested.
    let beside = archive.parent().ok_or("the archive has no directory")?;
    let scratch = beside.join(format!(".ksrv-{}-{}", server.name, std::process::id()));
    let _ = std::fs::remove_dir_all(&scratch);
    std::fs::create_dir_all(&scratch).map_err(|e| format!("cannot create {}: {e}", scratch.display()))?;

    let uid = service_uid();
    match uid {
        Some(n) => println!("release-server-test: running as root, so each installed binary runs as uid {n}, a number no user here has, and the verbs as root"),
        None => println!("release-server-test: not running as root (or no setpriv), so the installed binaries run as this user: the service's own uid is not exercised"),
    }
    let result = (|| {
        let root = install_into(&archive, server, &scratch.join("host"), uid)?;
        install_addressed(&archive, server, &scratch.join("addressed-host"), uid)?;
        match server.name {
            "relay" => {
                let mut relay = start_relay(&root, &scratch, uid)?;
                let r = health(relay.port)
                    .map(|body| {
                        println!("release-server-test: the installed relay answered /health: {body}");
                    })
                    .and_then(|()| holds_uid(&relay.child, "kotton-relay", uid))
                    .and_then(|()| match uid {
                        Some(n) => operator_verb_as_the_relays_user(&root, n),
                        None => Ok(()),
                    });
                stop(&mut relay.child);
                r
            }
            _ => {
                let relay_archive = relay.ok_or("the vault's test needs a relay archive (--relay)")?;
                let relay_archive = relay_archive
                    .canonicalize()
                    .map_err(|e| format!("cannot read {}: {e}", relay_archive.display()))?;
                println!("release-server-test: the vault's relay is {}", relay_archive.display());
                let relay_root = install_into(&relay_archive, &RELAY, &scratch.join("relay-host"), uid)?;
                let mut relay = start_relay(&relay_root, &scratch, uid)?;
                let r = health(relay.port).and_then(|_| start_vault(&root, &scratch, relay.port, uid));
                stop(&mut relay.child);
                r
            }
        }
    })();
    if result.is_ok() {
        let _ = std::fs::remove_dir_all(&scratch);
    } else {
        eprintln!("release-server-test: left {} for inspection", scratch.display());
    }
    result
}

/// The operator key step 3 creates each instance for: ed25519's base point, a key
/// whose secret half nobody holds.
const OPERATOR_KEY: &str = "5866666666666666666666666666666666666666666666666666666666666666";

/// The address step 3's stand-in ssh session arrived at: a documentation address
/// (RFC 5737), public in form, so the installer proposes it without calling it private.
const SSH_ARRIVED_AT: &str = "198.51.100.7";

/// The address step 6 gives the installer as `KOTTON_PUBLIC_ADDR`: another documentation
/// address (RFC 5737), not the one the ssh session arrived at, so the line naming it shows
/// the address given was the one written.
const GIVEN_ADDR: &str = "192.0.2.10";

/// Steps 1–4: check, unpack, sum, install into `root`, and read what the binary needs.
/// With `uid`, the user install.sh makes is that uid ([`StandInSystem`]).
fn install_into(archive: &Path, server: &Server, root: &Path, uid: Option<u32>) -> Result<PathBuf, String> {
    let (unpacked, dir) = unpack(archive, server, root)?;

    // 3. The installer, into a root of its own, with the user database stood in for:
    // the test makes no user on the machine it runs on, and reads what install.sh
    // asked of the system instead. Run as from an ssh session with no terminal, as a
    // person's `ssh <host> sh install.sh` runs it: the installer proposes the address the
    // session arrived at, and with nobody to say yes, writes nothing for it.
    std::fs::create_dir_all(root).map_err(|e| e.to_string())?;
    let system = StandInSystem::new(&root.with_extension("system"), 0, uid)?;
    let out = system
        .command("/bin/sh")
        .arg(dir.join("install.sh"))
        .env("KOTTON_ROOT", root)
        .env("KOTTON_OPERATOR_KEY", OPERATOR_KEY)
        .env("SSH_CONNECTION", format!("203.0.113.40 52814 {SSH_ARRIVED_AT} 22"))
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("cannot run install.sh: {e}"))?;
    if !out.status.success() {
        return Err(format!("install.sh failed:\n{}", release::said(&out)));
    }
    let said = String::from_utf8_lossy(&out.stdout);
    for line in ["systemctl daemon-reload", &format!("systemctl enable --now kotton-{}", server.name)] {
        if !said.contains(line) {
            return Err(format!("install.sh did not print `{line}`:\n{said}"));
        }
    }
    // Given the operator's key, the install created the instance as its user and ended
    // on its line (RFC-0084 V18).
    let last = instance_line(server, &said)?;
    println!("release-server-test: {} — install.sh created it for the operator's key and ended on its line: {last}", server.name);
    created_as_its_user(root, server, &system, uid)?;
    // Both ask for the host's address the same way: the vault's KOTTON_PUBLIC_ADDR, the
    // relay's KOTTON_RELAY_ADVERTISE (TASK-the-installer-tells-the-relay-the-address-it-announces).
    let line = format!("KOTTON_PUBLIC_ADDR={SSH_ARRIVED_AT} sh '{}'", dir.join("install.sh").display());
    if !said.lines().any(|l| l.trim() == line) {
        return Err(format!("install.sh, from an ssh session with no terminal, did not print `{line}` to run:\n{said}"));
    }
    wrote_no_address(root, server)?;
    println!(
        "release-server-test: {} — from an ssh session with no terminal, install.sh proposed {SSH_ARRIVED_AT}, printed the line that writes it, and wrote none",
        server.name
    );
    std::fs::remove_dir_all(&unpacked).map_err(|e| e.to_string())?;
    holds_its_install(root, server, &system)?;
    Ok(root.to_path_buf())
}

/// That the settings `server`'s install wrote under `root` leave its address empty: nobody
/// said yes to one.
fn wrote_no_address(root: &Path, server: &Server) -> Result<(), String> {
    let empty = if server.name == VAULT.name { "KOTTON_PUBLIC_ADDR=" } else { "KOTTON_RELAY_ADVERTISE=" };
    let written = std::fs::read_to_string(root.join("etc/kotton").join(server.env())).map_err(|e| e.to_string())?;
    if !written.lines().any(|l| l == empty) {
        return Err(format!("install.sh wrote an address nobody said yes to:\n{written}"));
    }
    Ok(())
}

/// What an install of `server` under `root` placed, read back: its unit in the form it is read
/// in, every path the unit names placed, its env file's mode, the user the unit runs as made
/// by `useradd` and given the env file's group where it should be, and its binary static.
fn holds_its_install(root: &Path, server: &Server, system: &StandInSystem) -> Result<(), String> {
    let unit = std::fs::read_to_string(root.join("etc/systemd/system").join(server.unit()))
        .map_err(|e| format!("install.sh placed no unit: {e}"))?;
    unit_normal_form(&unit, server.own_service_keys).map_err(|e| format!("the installed {} is not in the form it is read in: {e}", server.unit()))?;
    for (key, path) in unit_paths(&unit) {
        if !root.join(path.trim_start_matches('/')).exists() {
            return Err(format!("the unit's {key}={path} names nothing install.sh placed"));
        }
    }
    let env = root.join("etc/kotton").join(server.env());
    let mode = file_mode(&env)?;
    if mode != server.env_mode() {
        return Err(format!(
            "{} is mode {mode:o}; it holds a bucket's keys when one is used, and must be {:o}",
            env.display(),
            server.env_mode()
        ));
    }
    // The user the unit runs as is the one install.sh made.
    let user = unit_value(&unit, "User").ok_or("the unit names no User=")?;
    let asked = system.asked();
    let line = useradd_line(&user, server.name);
    if !asked.lines().any(|l| l == line) {
        return Err(format!("install.sh never made the unit's user — no `{line}` among what it asked of the system:\n{asked}"));
    }
    let chgrp = format!("chgrp {user} {}", env.display());
    if (server.env_mode() == 0o640) != asked.lines().any(|l| l == chgrp) {
        return Err(format!("{} is mode {mode:o}, and install.sh asked `{chgrp}` of the system only if it should be 640:\n{asked}", env.display()));
    }
    println!(
        "release-server-test: {} — install.sh made the user {user} the unit runs as, placed bin, unit and env file under a clean root, and printed the systemctl lines",
        server.name
    );

    // 4. What it needs of the host: nothing.
    let bin = root.join("usr/local/bin").join(server.binary);
    let bytes = std::fs::read(&bin).map_err(|e| e.to_string())?;
    static_or_refused(&bytes, server.binary)?;
    println!("release-server-test: {} is static — no PT_INTERP, so no loader to take a library from the host", server.binary);
    Ok(())
}

/// Steps 1–2 into `root`'s `.unpacked` sibling: the archive's listing held to the layout,
/// unpacked, and its files held to `SHA256SUMS`. Returns that directory and the archive's
/// top directory in it.
fn unpack(archive: &Path, server: &Server, root: &Path) -> Result<(PathBuf, PathBuf), String> {
    unpack_as(archive, server.name, &server.entries(), &[crate::license_check::FILE.to_string()], root)
}

/// [`unpack`], for an archive named `what` whose layout is `entries` and whose
/// `THIRD-PARTY-NOTICES` are `notices`, each held to that file's shape. Every `SHA256SUMS` the
/// layout names is checked where it lies, the top one first.
fn unpack_as(archive: &Path, what: &str, entries: &[String], notices: &[String], root: &Path) -> Result<(PathBuf, PathBuf), String> {
    // 1. What is in it.
    let listing = Command::new("tar")
        .arg("-tzf")
        .arg(archive)
        .output()
        .map_err(|e| format!("cannot run tar: {e}"))?;
    if !listing.status.success() {
        return Err(format!("tar cannot list {}", archive.display()));
    }
    let listed = String::from_utf8_lossy(&listing.stdout).to_string();
    release::check_layout(&listed, entries)?;
    let verbose = Command::new("tar")
        .arg("-tvzf")
        .arg(archive)
        .output()
        .map_err(|e| format!("cannot run tar: {e}"))?;
    release::check_entry_types(&String::from_utf8_lossy(&verbose.stdout))?;
    let top = listed
        .lines()
        .next()
        .and_then(|l| l.split('/').next())
        .ok_or("the archive is empty")?
        .to_string();

    // 2. Unpack, and the sums.
    let unpacked = root.with_extension("unpacked");
    let _ = std::fs::remove_dir_all(&unpacked);
    std::fs::create_dir_all(&unpacked).map_err(|e| e.to_string())?;
    let st = Command::new("tar")
        .arg("-xzf")
        .arg(archive)
        .arg("-C")
        .arg(&unpacked)
        .status()
        .map_err(|e| format!("cannot run tar: {e}"))?;
    if !st.success() {
        return Err("tar could not unpack the archive".into());
    }
    let dir = unpacked.join(&top);
    let mut sums: Vec<&String> = entries.iter().filter(|e| *e == "SHA256SUMS" || e.ends_with("/SHA256SUMS")).collect();
    sums.sort_by_key(|e| e.matches('/').count());
    for sum in sums {
        let at = dir.join(sum).parent().map(Path::to_path_buf).unwrap_or_else(|| dir.clone());
        let out = clean(Command::new("sha256sum"))
            .args(["-c", "SHA256SUMS"])
            .current_dir(&at)
            .output()
            .map_err(|e| format!("cannot run sha256sum: {e}"))?;
        if !out.status.success() {
            return Err(format!("the unpacked files are not the ones {sum} names:\n{}", release::said(&out)));
        }
        println!("release-server-test: {what} — sha256sum -c {sum}: every file matches");
    }
    for file in notices {
        let text = std::fs::read_to_string(dir.join(file)).map_err(|e| format!("the archive carries no readable {file}: {e}"))?;
        let listed = crate::license_check::check_notices(&text)?;
        println!("release-server-test: {what} — {file} lists {listed} third-party packages");
    }

    Ok((unpacked, dir))
}

/// The line install.sh, given the operator's key, ends on (RFC-0084 V18): the last of
/// `said`, the instance's.
fn instance_line<'a>(server: &Server, said: &'a str) -> Result<&'a str, String> {
    let last = said.lines().last().unwrap_or("");
    let prefix = format!("kotton-instance:{}:", server.name);
    if !last.starts_with(&prefix) {
        return Err(format!("install.sh, given KOTTON_OPERATOR_KEY, did not end on the {}'s line:\n{said}", server.name));
    }
    Ok(last)
}

/// That install.sh's `create` ran as the service's user, read from what it left before
/// anything of this test touches it: install.sh asked `runuser -u kotton-<name> --` for
/// it, and — with `uid`, where that user is the uid — the state directory is the uid's and
/// `0700`, everything `create` made in it is the uid's, and the vault's settings are root's,
/// group the uid's and `0640`, so `create` read them by group alone. The state is the one
/// the installed settings name, under `root`, as install.sh finds it.
fn created_as_its_user(root: &Path, server: &Server, system: &StandInSystem, uid: Option<u32>) -> Result<(), String> {
    let user = format!("kotton-{}", server.name);
    let asked = system.asked();
    let runuser = format!("runuser -u {user} -- {}", root.join("usr/local/bin").join(server.binary).display());
    if !asked.lines().any(|l| l.starts_with(&runuser)) {
        return Err(format!("install.sh did not run `create` as {user}: no `{runuser} …` among what it asked of the system:\n{asked}"));
    }
    let Some(n) = uid else {
        println!("release-server-test: {} — install.sh asked `runuser -u {user}` for `create`; not root here, so it ran as this user", server.name);
        return Ok(());
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        let env = root.join("etc/kotton").join(server.env());
        let state_var = if server.name == VAULT.name { "KOTTON_BASE_DIR" } else { "KOTTON_RELAY_STATE_DIR" };
        let text = std::fs::read_to_string(&env).map_err(|e| format!("{}: {e}", env.display()))?;
        let pairs = env_pairs(&text).map_err(|e| format!("{}: {e}", env.display()))?;
        let named = pairs
            .iter()
            .rev()
            .find(|(k, v)| k == state_var && !v.is_empty())
            .map(|(_, v)| v.clone())
            .unwrap_or_else(|| format!("/var/lib/{user}"));
        let state = root.join(named.trim_start_matches('/'));
        let meta = std::fs::metadata(&state).map_err(|e| format!("{}: {e}", state.display()))?;
        if (meta.uid(), meta.gid(), meta.mode() & 0o777) != (n, n, 0o700) {
            return Err(format!(
                "{} is uid {}, gid {}, mode {:o} after install.sh: not the service's {n}, {n}, 700",
                state.display(),
                meta.uid(),
                meta.gid(),
                meta.mode() & 0o777
            ));
        }
        let mut made = Vec::new();
        let mut stack = vec![state.clone()];
        while let Some(d) = stack.pop() {
            for e in std::fs::read_dir(&d).map_err(|e| format!("{}: {e}", d.display()))?.flatten() {
                let m = e.path().symlink_metadata().map_err(|err| format!("{}: {err}", e.path().display()))?;
                if m.uid() != n {
                    return Err(format!("`create` made {} as uid {}, not the service's {n}", e.path().display(), m.uid()));
                }
                if m.is_dir() {
                    stack.push(e.path());
                }
                made.push(e.path());
            }
        }
        if made.is_empty() {
            return Err(format!("`create` made nothing in {}", state.display()));
        }
        let m = std::fs::metadata(&env).map_err(|e| format!("{}: {e}", env.display()))?;
        let want = if server.env_mode() == 0o640 { (0, n, 0o640) } else { (0, 0, 0o600) };
        if (m.uid(), m.gid(), m.mode() & 0o777) != want {
            return Err(format!(
                "{} is uid {}, gid {}, mode {:o} after install.sh, not {}, {}, {:o}",
                env.display(),
                m.uid(),
                m.gid(),
                m.mode() & 0o777,
                want.0,
                want.1,
                want.2
            ));
        }
        println!(
            "release-server-test: {} — install.sh ran `create` as {user}, uid {n}: {} is uid {n}'s and 0700, the {} entries `create` made in it are uid {n}'s, and {} is {}",
            server.name,
            state.display(),
            made.len(),
            env.display(),
            if server.env_mode() == 0o640 { format!("root's, group {n}, 0640 — read by group alone") } else { "root's alone, 0600".into() }
        );
    }
    Ok(())
}

/// Step 6: install `archive` once more, into a clean `root`, given the host's address —
/// `KOTTON_PUBLIC_ADDR=`[`GIVEN_ADDR`], from the same ssh session, so the address given and
/// not the one arrived at is what is written — and hold the line install.sh ends on to name
/// it. The relay's `create` is told it by `--advertise`, handed over `runuser`, since its
/// user cannot read relay.env; the vault's reads it from vault.env. `create` again runs as
/// the service's user ([`created_as_its_user`]).
fn install_addressed(archive: &Path, server: &Server, root: &Path, uid: Option<u32>) -> Result<(), String> {
    let (unpacked, dir) = unpack(archive, server, root)?;
    std::fs::create_dir_all(root).map_err(|e| e.to_string())?;
    let system = StandInSystem::new(&root.with_extension("system"), 0, uid)?;
    let out = system
        .command("/bin/sh")
        .arg(dir.join("install.sh"))
        .env("KOTTON_ROOT", root)
        .env("KOTTON_OPERATOR_KEY", OPERATOR_KEY)
        .env("KOTTON_PUBLIC_ADDR", GIVEN_ADDR)
        .env("SSH_CONNECTION", format!("203.0.113.40 52814 {SSH_ARRIVED_AT} 22"))
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("cannot run install.sh: {e}"))?;
    if !out.status.success() {
        return Err(format!("install.sh, given KOTTON_PUBLIC_ADDR={GIVEN_ADDR}, failed:\n{}", release::said(&out)));
    }
    let said = String::from_utf8_lossy(&out.stdout);
    let last = instance_line(server, &said)?;
    let hint = last.rsplit_once('@').map(|(_, h)| h).unwrap_or("");
    if !hint.contains(GIVEN_ADDR) {
        return Err(format!(
            "install.sh, given KOTTON_PUBLIC_ADDR={GIVEN_ADDR}, ended on a line that does not name it after its `@`: {last}\n{said}"
        ));
    }
    if server.name == RELAY.name {
        let advertise = format!("--advertise http://{GIVEN_ADDR}:");
        let asked = system.asked();
        if !asked.lines().any(|l| l.starts_with("runuser -u kotton-relay -- ") && l.contains(&advertise)) {
            return Err(format!("install.sh did not hand the relay's `create` `{advertise}…` over runuser:\n{asked}"));
        }
    }
    created_as_its_user(root, server, &system, uid)?;
    println!("release-server-test: {} — given KOTTON_PUBLIC_ADDR={GIVEN_ADDR}, install.sh ended on a line that names it: {last}", server.name);
    std::fs::remove_dir_all(&unpacked).map_err(|e| e.to_string())?;
    Ok(())
}

/// The key the host's test creates its vault for, beside [`OPERATOR_KEY`] for its relay: the
/// public key of RFC 8032's first test vector, whose secret half is published, so it operates
/// nothing anybody holds alone. Another key than the relay's, since one key never operates two
/// instances and the host's installer refuses one given twice.
const VAULT_OPERATOR_KEY: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";

/// The line the host's install.sh ends on, as the lines it names: one row, the relay's line and
/// the vault's with one space between, each beginning as its server's does. Read the way
/// `kotton enrol` reads it — split on whitespace, which no line holds.
fn host_line(said: &str) -> Result<Vec<(Server, &str)>, String> {
    let last = said.lines().last().unwrap_or("");
    let words: Vec<&str> = last.split_whitespace().collect();
    if words.len() != SERVERS.len() || last.trim() != words.join(" ") {
        return Err(format!("the host's install.sh did not end on one row holding the relay's line and the vault's, one space between:\n{said}"));
    }
    SERVERS
        .into_iter()
        .zip(words)
        .map(|(server, word)| {
            if word.starts_with(&format!("kotton-instance:{}:", server.name)) {
                Ok((server, word))
            } else {
                Err(format!("the host's line names `{word}` where the {}'s line goes:\n{said}", server.name))
            }
        })
        .collect()
}

/// Install the host's `archive` into a clean root and start both servers from there: the
/// steps [`server_test`] takes for one server, taken for the two the host's install.sh
/// installs together.
///
/// 1–2. the listing held to [`host_entries`], each `SHA256SUMS` checked, both trees'
///    `THIRD-PARTY-NOTICES` held to that file's shape;
/// 3. the host's install.sh, given a key for each, from an ssh session with no terminal:
///    each server placed and created as its own user ([`holds_its_install`],
///    [`created_as_its_user`]), the line that writes the address printed once and naming the
///    host's install.sh, no address written, the systemctl line it did not run (it was given
///    `KOTTON_ROOT`) printed, and its last output the host's line ([`host_line`]);
/// 4. both binaries static;
/// 5. the relay started from that root and `/health` read, then the vault beside it;
/// 6. installed once more, given `KOTTON_PUBLIC_ADDR`, and both halves of the host's line
///    naming it.
pub(crate) fn host_test(archive: &Path) -> Result<(), String> {
    let archive = archive
        .canonicalize()
        .map_err(|e| format!("cannot read {}: {e}", archive.display()))?;
    let beside = archive.parent().ok_or("the archive has no directory")?;
    let scratch = beside.join(format!(".ksrv-{HOST}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&scratch);
    std::fs::create_dir_all(&scratch).map_err(|e| format!("cannot create {}: {e}", scratch.display()))?;
    let uid = service_uid();
    match uid {
        Some(n) => println!("release-server-test: running as root, so each installed binary runs as uid {n}, a number no user here has, and the verbs as root"),
        None => println!("release-server-test: not running as root (or no setpriv), so the installed binaries run as this user: the service's own uid is not exercised"),
    }
    let result = (|| {
        let root = install_host_into(&archive, &scratch.join("host"), uid, None)?;
        install_host_into(&archive, &scratch.join("addressed-host"), uid, Some(GIVEN_ADDR))?;
        let mut relay = start_relay(&root, &scratch, uid)?;
        let r = health(relay.port)
            .map(|body| println!("release-server-test: the host's relay answered /health: {body}"))
            .and_then(|()| holds_uid(&relay.child, "kotton-relay", uid))
            .and_then(|()| match uid {
                Some(n) => operator_verb_as_the_relays_user(&root, n),
                None => Ok(()),
            })
            .and_then(|()| start_vault(&root, &scratch, relay.port, uid));
        stop(&mut relay.child);
        r
    })();
    if result.is_ok() {
        let _ = std::fs::remove_dir_all(&scratch);
    } else {
        eprintln!("release-server-test: left {} for inspection", scratch.display());
    }
    result
}

/// Steps 1–4 of [`host_test`], or with `addr` step 6, into `root`.
fn install_host_into(archive: &Path, root: &Path, uid: Option<u32>, addr: Option<&str>) -> Result<PathBuf, String> {
    let notices: Vec<String> = SERVERS.iter().map(|s| format!("{}/{}", s.name, crate::license_check::FILE)).collect();
    let (unpacked, dir) = unpack_as(archive, HOST, &host_entries(), &notices, root)?;
    std::fs::create_dir_all(root).map_err(|e| e.to_string())?;
    let system = StandInSystem::new(&root.with_extension("system"), 0, uid)?;
    let mut c = system.command("/bin/sh");
    c.arg(dir.join("install.sh"))
        .env("KOTTON_ROOT", root)
        .env("KOTTON_OPERATOR_KEY_RELAY", OPERATOR_KEY)
        .env("KOTTON_OPERATOR_KEY_VAULT", VAULT_OPERATOR_KEY)
        .env("SSH_CONNECTION", format!("203.0.113.40 52814 {SSH_ARRIVED_AT} 22"))
        .stdin(Stdio::null());
    if let Some(a) = addr {
        c.env("KOTTON_PUBLIC_ADDR", a);
    }
    let out = c.output().map_err(|e| format!("cannot run the host's install.sh: {e}"))?;
    if !out.status.success() {
        return Err(format!("the host's install.sh failed:\n{}", release::said(&out)));
    }
    let said = String::from_utf8_lossy(&out.stdout).to_string();
    let lines = host_line(&said)?;
    let start = "systemctl daemon-reload && systemctl enable --now kotton-relay kotton-vault";
    if !said.lines().any(|l| l.trim() == start) {
        return Err(format!("the host's install.sh, given KOTTON_ROOT, did not print `{start}`, the start it did not run:\n{said}"));
    }
    for (server, line) in &lines {
        created_as_its_user(root, server, &system, uid)?;
        holds_its_install(root, server, &system)?;
        match addr {
            None => wrote_no_address(root, server)?,
            Some(a) => {
                if !line.rsplit_once('@').is_some_and(|(_, hint)| hint.contains(a)) {
                    return Err(format!("given KOTTON_PUBLIC_ADDR={a}, the host's line names the {} without it after its `@`: {line}", server.name));
                }
            }
        }
    }
    if addr.is_none() {
        let again = format!("KOTTON_PUBLIC_ADDR={SSH_ARRIVED_AT} sh '{}'", dir.join("install.sh").display());
        let n = said.lines().filter(|l| l.trim() == again).count();
        if n != 1 {
            return Err(format!("from an ssh session with no terminal, the host's install.sh printed `{again}` {n} times, not once:\n{said}"));
        }
    }
    println!("release-server-test: {HOST} — install.sh installed and created both, and ended on one line naming both: {}", said.lines().last().unwrap_or(""));
    std::fs::remove_dir_all(&unpacked).map_err(|e| e.to_string())?;
    Ok(root.to_path_buf())
}

/// A released binary is static: no `PT_INTERP`, and so no loader to resolve a `NEEDED`
/// library from the host. Anything else is refused by name.
pub(crate) fn static_or_refused(bytes: &[u8], binary: &str) -> Result<(), String> {
    match elf_interpreter(bytes)? {
        None => Ok(()),
        Some(interp) => Err(format!(
            "{binary} asks for the loader {interp}, so the host's libraries are part of what runs and the archive's sum does not name them — a release is built for {TARGET} and is static"
        )),
    }
}

/// What install.sh asks `useradd` for: a system user with a group of its own name, no
/// home made, no shell, and `/var/lib/<user>` — the state directory — named as its home.
fn useradd_line(user: &str, name: &str) -> String {
    format!(
        "useradd --system --user-group --no-create-home --home-dir /var/lib/{user} --shell /usr/sbin/nologin --comment Kotton {name} {user}"
    )
}

/// The longest line a unit in [`unit_normal_form`] may hold, in bytes.
const UNIT_LINE_MAX: usize = 1000;

/// The sections a unit has, in the order it has them. A unit is ours, so it is written
/// in one form, and a unit that leaves it is refused rather than read.
const UNIT_SECTIONS: [&str; 3] = ["[Unit]", "[Service]", "[Install]"];

/// The keys each of [`UNIT_SECTIONS`] may carry, and no other: the ones both shipped units
/// say (`TASK-a-service-key-the-normal-form-does-not-name-passes-both-unit-tests`). A
/// `[Service]` key only one unit says is that [`Server`]'s `own_service_keys`, so the relay
/// cannot say the vault's `RuntimeDirectory=` and take its door's directory. A key
/// is refused by what it is not — named here — rather than by what it is, because the
/// keys that undo a unit's confinement (`ExecStartPre=+…`, `AmbientCapabilities=`,
/// `PermissionsStartOnly=`, a drop-in's worth of others) are a list systemd grows and
/// this file never would. A key a unit needs is added here in the same change as the
/// unit, and `every_key_the_normal_form_names_is_one_a_unit_says` refuses one a unit
/// does not say.
const UNIT_KEYS: [&[&str]; 3] = [
    &["Description", "Documentation", "Wants", "After"],
    &[
        "User",
        "Group",
        "EnvironmentFile",
        "ExecStart",
        "Restart",
        "RestartSec",
        "StateDirectory",
        "StateDirectoryMode",
        "NoNewPrivileges",
        "ProtectSystem",
        "ProtectHome",
        "PrivateTmp",
        "UMask",
        "CapabilityBoundingSet",
        "PrivateDevices",
        "ProtectKernelTunables",
        "ProtectKernelModules",
        "ProtectKernelLogs",
        "ProtectControlGroups",
        "ProtectClock",
        "ProtectHostname",
        "RestrictSUIDSGID",
        "RestrictNamespaces",
        "LockPersonality",
        "SystemCallArchitectures",
        "RestrictAddressFamilies",
        "SystemCallFilter",
        "SystemCallErrorNumber",
        "RemoveIPC",
        "MemoryDenyWriteExecute",
        "RestrictRealtime",
        "ProtectProc",
        "ProcSubset",
        "PrivateUsers",
    ],
    &["WantedBy"],
];

/// Whether `unit` is in the one form the units here are written in, which is a form a
/// reader cannot read two ways (`TASK-the-relay-and-the-vault-units-are-still-rated-exposed`).
/// `Err` names the first line that leaves it.
///
/// - `[Unit]`, `[Service]` and `[Install]` once each, in that order, and no other section,
///   `X-` sections included.
/// - Every other line is blank, a comment, or a directive. A comment is its own line,
///   begins with `#`, and does not end in `\`.
/// - A directive is `Key=value`. The key is letters and digits, with no whitespace around
///   `=` and none at either end of the line. The value is printable ASCII and does not
///   end in `\`, so no line continues into the next.
/// - The key is one [`UNIT_KEYS`] names for its section, or, in `[Service]`, one of `own`:
///   the keys this unit says that the other does not. Any other is refused, however it is
///   spelled, so what a unit may say is a list and not whatever systemd reads.
/// - Each key is said once in its section, except `SystemCallFilter=`, which accumulates.
/// - No line, comment or directive, holds a control character (a carriage return, a NUL,
///   a tab among them: systemd ends a line at `\r` and NUL) or a byte-order mark.
/// - No line is longer than [`UNIT_LINE_MAX`] bytes. systemd refuses a whole unit with a
///   line over 1 MiB, so the bound sits far below that and far above any line the units
///   hold.
///
/// systemd reads more spellings than these. Refusing them here is what makes
/// [`unit_values`] exact without re-implementing systemd's parser.
pub(crate) fn unit_normal_form(unit: &str, own: &[&str]) -> Result<(), String> {
    let mut next = 0;
    let mut section: Option<(&str, &[&str])> = None;
    let mut said: Vec<(&str, &str)> = Vec::new();
    for (i, line) in unit.split('\n').enumerate() {
        let n = i + 1;
        let refuse = |why: &str| Err(format!("line {n}: {why}: `{}`", line.escape_debug()));
        // systemd refuses a whole unit with a line over 1 MiB.
        if line.len() > UNIT_LINE_MAX {
            return Err(format!("line {n}: {} bytes, longer than {UNIT_LINE_MAX}", line.len()));
        }
        // systemd ends a line at `\n`, `\r` and NUL, so any control character, in a
        // comment as much as in a directive, is refused rather than guessed at.
        if line.chars().any(|c| c.is_control()) || line.contains('\u{feff}') {
            return refuse("a control character or byte-order mark");
        }
        if line.is_empty() {
            continue;
        }
        if line.starts_with('#') {
            if line.ends_with('\\') {
                return refuse("a comment ending in `\\`");
            }
            continue;
        }
        if line.starts_with('[') {
            if UNIT_SECTIONS.get(next) != Some(&line) {
                return refuse(&format!("the section here is {}", UNIT_SECTIONS.get(next).unwrap_or(&"none")));
            }
            section = Some((line, UNIT_KEYS[next]));
            next += 1;
            continue;
        }
        let Some((in_section, keys)) = section else {
            return refuse("a line before [Unit]");
        };
        let Some((key, value)) = line.split_once('=') else {
            return refuse("not blank, a `#` comment, a section or `Key=value`");
        };
        if key.is_empty() || !key.chars().all(|c| c.is_ascii_alphanumeric()) {
            return refuse("a key that is not letters and digits, or whitespace before `=`");
        }
        if value.starts_with(' ') || value.ends_with(' ') || value.ends_with('\\') {
            return refuse("whitespace after `=` or at the end, or a `\\` that continues the line");
        }
        if !value.chars().all(|c| c == ' ' || c.is_ascii_graphic()) {
            return refuse("a value that is not printable ASCII");
        }
        let named = keys.contains(&key) || (in_section == "[Service]" && own.contains(&key));
        if !named {
            return refuse(&format!("{key}= is not a key the normal form names for {in_section}"));
        }
        if key != "SystemCallFilter" && said.contains(&(in_section, key)) {
            return refuse(&format!("{key}= said twice in {in_section}"));
        }
        said.push((in_section, key));
    }
    if next != UNIT_SECTIONS.len() {
        return Err(format!("the unit has no {} section", UNIT_SECTIONS[next]));
    }
    Ok(())
}

/// The value of a `[Service]` key, the last one if it is said twice, from a unit in
/// [`unit_normal_form`].
pub(crate) fn unit_value(unit: &str, key: &str) -> Option<String> {
    unit_values(unit, key).pop()
}

/// Every value a unit's `[Service]` section gives `key`, in order. Exact on a unit in
/// [`unit_normal_form`], and meant for nothing else: every caller holds the unit to that
/// form first.
pub(crate) fn unit_values(unit: &str, key: &str) -> Vec<String> {
    let mut in_service = false;
    let mut values = Vec::new();
    for line in unit.lines() {
        if line.starts_with('[') {
            in_service = line == "[Service]";
        } else if let (true, Some((k, v))) = (in_service, line.split_once('=')) {
            if k == key && !line.starts_with('#') {
                values.push(v.to_string());
            }
        }
    }
    values
}

/// The commands install.sh asks of the system's user database — `id`, `getent`,
/// `useradd` — and of the users it makes — `chown`, `chgrp`, `runuser` — as scripts that
/// write each call down, first on a `PATH` of the system directories. `id -u` says `uid`;
/// `useradd` adds the name to the users `getent passwd` then finds, and changes nothing on
/// this machine.
///
/// Given `service`, a uid no user of this machine has ([`service_uid`]), a user `useradd`
/// made *is* that number to the other three, and they act: `chown` and `chgrp` give the
/// path to it, and `runuser -u <user> --` runs the command as it, through `setpriv`, its
/// group the same number and no other — so the installer's `create` runs as the service's
/// uid, on a state directory that uid owns, reading the vault's settings by group alone
/// (`TASK-release-server-test-runs-the-installers-create-as-root-and-never-with-an-address`).
/// A name `useradd` did not make goes to this machine's own `chown`, `chgrp` and `runuser`
/// unchanged. Given none — not root, where no other uid can be entered — `chown` and
/// `chgrp` change nothing and `runuser` runs the command as this process, and the test
/// that installs says so.
struct StandInSystem {
    dir: PathBuf,
    log: PathBuf,
}

/// The stood-in `chown`, `chgrp` and `runuser` (see [`StandInSystem`]) for a user
/// database whose made users are the uid `service`, or `None` for the forms that only
/// write the call down.
fn stood_in_owners(log: &str, users: &str, service: Option<u32>) -> [(&'static str, String); 3] {
    let Some(n) = service else {
        return [
            // The group is the stood-in user's, which this machine does not have.
            ("chgrp", format!("echo \"chgrp $*\" >> '{log}'")),
            // So is the owner of the state directory the installer makes.
            ("chown", format!("echo \"chown $*\" >> '{log}'")),
            // `create`, as the stood-in user: asked, and run as this process's.
            ("runuser", format!("echo \"runuser $*\" >> '{log}'\nwhile [ \"$1\" != -- ]; do shift; done\nshift\nexec \"$@\"")),
        ];
    };
    let path = release::SYSTEM_PATH;
    // A made user's name is its number; any other name is this machine's to resolve.
    let id = format!("id_of() {{ if grep -qx \"$1\" '{users}'; then echo {n}; else printf '%s' \"$1\"; fi; }}");
    [
        (
            "chgrp",
            format!("echo \"chgrp $*\" >> '{log}'\n{id}\ng=$(id_of \"$1\")\nshift\nPATH='{path}'\nexport PATH\nexec chgrp \"$g\" \"$@\""),
        ),
        (
            "chown",
            format!(
                "echo \"chown $*\" >> '{log}'\n{id}\ncase \"$1\" in *:*) o=\"$(id_of \"${{1%%:*}}\"):$(id_of \"${{1#*:}}\")\" ;; *) o=$(id_of \"$1\") ;; esac\nshift\nPATH='{path}'\nexport PATH\nexec chown \"$o\" \"$@\""
            ),
        ),
        // What `runuser -u <user> -- <command>` does for a user with no other groups: the
        // command, run as the user's uid and group, with HOME, SHELL, USER and LOGNAME the
        // user's (`useradd_line`'s home and shell) and the rest of the environment kept.
        (
            "runuser",
            format!(
                "echo \"runuser $*\" >> '{log}'\n[ \"$1\" = -u ] && [ \"$3\" = -- ] || {{ echo \"runuser: the stand-in takes -u <user> -- <command>, not: $*\" >&2; exit 1; }}\nuser=$2\nshift 3\nPATH='{path}'\nexport PATH\ngrep -qx \"$user\" '{users}' || exec runuser -u \"$user\" -- \"$@\"\nexport HOME=\"/var/lib/$user\" SHELL=/usr/sbin/nologin USER=\"$user\" LOGNAME=\"$user\"\nexec setpriv --reuid {n} --regid {n} --clear-groups -- \"$@\""
            ),
        ),
    ]
}

impl StandInSystem {
    fn new(dir: &Path, uid: u32, service: Option<u32>) -> Result<Self, String> {
        let _ = std::fs::remove_dir_all(dir);
        std::fs::create_dir_all(dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
        let log = dir.join("asked");
        let users = dir.join("users");
        std::fs::write(&log, "").map_err(|e| e.to_string())?;
        std::fs::write(&users, "").map_err(|e| e.to_string())?;
        let groups = dir.join("groups");
        std::fs::write(&groups, "").map_err(|e| e.to_string())?;
        let (log_s, users_s) = (log.display().to_string(), users.display().to_string());
        let groups_s = groups.display().to_string();
        let name = if uid == 0 { "root" } else { "someone" };
        for (cmd, body) in [
            ("id", format!("case \"$1\" in -u) echo {uid} ;; -un) echo {name} ;; *) exit 1 ;; esac")),
            // A group line only where the test wrote one to `groups`: what `getent group` prints.
            (
                "getent",
                format!(
                    "echo \"getent $*\" >> '{log_s}'\n[ \"$1\" = group ] && {{ grep \"^$2:\" '{groups_s}'; exit; }}\n[ \"$1\" = passwd ] && grep -qx \"$2\" '{users_s}'"
                ),
            ),
            (
                "useradd",
                format!("echo \"useradd $*\" >> '{log_s}'\nfor last; do :; done\necho \"$last\" >> '{users_s}'"),
            ),
        ]
        .into_iter()
        .chain(stood_in_owners(&log_s, &users_s, service))
        {
            let path = dir.join(cmd);
            std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).map_err(|e| e.to_string())?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).map_err(|e| e.to_string())?;
            }
        }
        Ok(Self { dir: dir.to_path_buf(), log })
    }

    /// `program` with nothing of this machine's environment but these commands and the
    /// system `PATH`.
    fn command(&self, program: impl AsRef<std::ffi::OsStr>) -> Command {
        let mut c = Command::new(program);
        c.env_clear()
            .env("PATH", format!("{}:{}", self.dir.display(), release::SYSTEM_PATH));
        c
    }

    /// Every call made so far, one a line, in order.
    fn asked(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }
}

/// `EnvironmentFile=` and `ExecStart=` of a unit's `[Service]`, with the absolute path
/// each names, from a unit in [`unit_normal_form`].
pub(crate) fn unit_paths(unit: &str) -> Vec<(&'static str, String)> {
    ["EnvironmentFile", "ExecStart"]
        .into_iter()
        .flat_map(|k| unit_values(unit, k).into_iter().map(move |v| (k, v)))
        .map(|(k, v)| (k, v.split_whitespace().next().unwrap_or("").trim_start_matches('-').to_string()))
        .collect()
}

fn file_mode(path: &Path) -> Result<u32, String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        Ok(std::fs::metadata(path)
            .map_err(|e| format!("{}: {e}", path.display()))?
            .permissions()
            .mode()
            & 0o777)
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(0o600)
    }
}

/// The ELF's `PT_INTERP`: the dynamic loader it asks for, or `None` for a static binary.
pub(crate) fn elf_interpreter(bytes: &[u8]) -> Result<Option<String>, String> {
    let u16_at = |o: usize| bytes.get(o..o + 2).map(|b| u16::from_le_bytes([b[0], b[1]]));
    let u32_at = |o: usize| bytes.get(o..o + 4).map(|b| u32::from_le_bytes(b.try_into().unwrap()));
    let u64_at = |o: usize| bytes.get(o..o + 8).map(|b| u64::from_le_bytes(b.try_into().unwrap()));
    if bytes.get(..4) != Some(b"\x7fELF") || bytes.get(4) != Some(&2) || bytes.get(5) != Some(&1) {
        return Err("the binary is not a 64-bit little-endian ELF".into());
    }
    let bad = || "the ELF's program headers run past its end".to_string();
    let phoff = u64_at(0x20).ok_or_else(bad)? as usize;
    let phentsize = u16_at(0x36).ok_or_else(bad)? as usize;
    let phnum = u16_at(0x38).ok_or_else(bad)? as usize;
    for i in 0..phnum {
        let ph = phoff + i * phentsize;
        if u32_at(ph).ok_or_else(bad)? == 3 {
            let off = u64_at(ph + 8).ok_or_else(bad)? as usize;
            let size = u64_at(ph + 32).ok_or_else(bad)? as usize;
            let raw = bytes.get(off..off + size).ok_or_else(bad)?;
            return Ok(Some(String::from_utf8_lossy(raw).trim_end_matches('\0').to_string()));
        }
    }
    Ok(None)
}

/// A command with nothing of this machine's environment but the system `PATH`.
fn clean(mut c: Command) -> Command {
    c.env_clear().env("PATH", release::SYSTEM_PATH);
    c
}

/// `kvaultd`'s own reader of a host's settings file, compiled here from its one source
/// rather than linked: xtask taking `kvaultd` as a dependency would build tokio, sqlx and
/// SQLite into every `cargo xtask`, which `TASK-xtask-drags-in-the-whole-workspace` took
/// out, and a copy would be a second reader held to the first only by a test. The file
/// names nothing but `std`, which is what lets it be compiled in both crates.
#[path = "../../core/kvaultd/src/settings.rs"]
mod settings;

/// The installed env file as `KEY=value` pairs, read by `kvaultd::settings::env_file_pairs`
/// itself — the one plain form `install-server.sh`, systemd's `EnvironmentFile=` and
/// `kvaultd` read alike: one wrapping pair of quotes is not part of a value, and a line in
/// any other form is refused, naming it, rather than trimmed into a setting
/// (`TASK-release-server-tests-reader-of-the-env-file-is-not-the-plain-form`).
pub(crate) fn env_pairs(text: &str) -> Result<Vec<(String, String)>, String> {
    settings::env_file_pairs(text.as_bytes())
}

/// Where systemd's own settings parser is — `libsystemd-shared` and the `python3` the
/// settings differential calls it through — found by the one finder those tests use,
/// compiled here from its one source as `settings` is above. It names nothing but `std`.
#[path = "../../infra/relay/tests/common/systemds_parser.rs"]
pub(crate) mod systemds_parser;

/// Why no release may be cut on this machine, where systemd's parser is not on it.
///
/// The settings differential holds `install-server.sh`'s reading of a host's settings to
/// systemd's own `load_env_file`, and it can only do that where the library and `python3`
/// are; anywhere else it either fails or, with `KOTTON_NO_SYSTEMD_PARSER` set, reports itself
/// skipped. The release gate takes neither form: it does not read that variable, so an
/// archive is never cut on a machine where the comparison could not have been made
/// (`TASK-the-settings-differential-is-not-green-where-systemds-parser-is-absent`).
///
/// `release-server` asks it first, before the fetch and the build; its run of
/// [`SETTINGS_DIFFERENTIAL`] is what requires the parser, and this says so sooner.
/// `release-server-test` does not ask it: installing an archive compares nothing with the parser
/// (`TASK-the-release-gates-parser-presence-refusals-guard-what-the-differentials-run-now-proves`).
pub(crate) fn systemds_parser_refusal(found: Result<systemds_parser::SystemdsParser, String>) -> Option<String> {
    found.err().map(|missing| {
        format!(
            "systemd's own settings parser is not on this machine ({missing}). A release is cut only \
             where the installer's reading of a settings file can be held to it, and \
             KOTTON_NO_SYSTEMD_PARSER does not change that. `cargo xtask doctor --tier server` names \
             the packages"
        )
    })
}

/// The settings differential: the four tests that hold `install-server.sh`'s reading of a
/// host's settings file to systemd's own `load_env_file` — the relay's two, against its own
/// manifest, and `kvaultd`'s two, which add the vault's reader as a third column. Each pair is
/// the crate it is in, the test file it is in, and the two names.
///
/// `release-server` runs them itself, at the tree it is about to build, and names no archive
/// unless libtest says `ok` of each by name ([`differential_verdict`]): the proof is made by
/// the release, so there is no recorded result anywhere for a release to have to trust
/// (`TASK-the-release-gate-requires-systemds-parser-and-does-not-run-the-differential`).
const SETTINGS_DIFFERENTIAL: [(Source, &str, [&str; 2]); 2] = [
    (
        RELAY.source,
        "an_install_tells_the_relay_its_address",
        [
            "the_installer_reads_what_systemds_own_parser_reads",
            "generated_settings_the_installer_accepts_are_read_the_same_by_systemds_parser",
        ],
    ),
    (
        VAULT.source,
        "the_vault_reads_its_settings_as_the_installer_and_systemd_do",
        [
            "kvaultd_reads_the_fixed_forms_the_installer_accepts_as_the_installer_and_systemd_do",
            "kvaultd_reads_the_generated_forms_the_installer_accepts_as_the_installer_and_systemd_do",
        ],
    ),
];

/// What libtest said of `names`, from its output and the run's exit: `Ok` only where each
/// is reported `ok` by its exact name. `ignored` — the verdict a declared
/// `KOTTON_NO_SYSTEMD_PARSER`, or a `--cfg` nobody meant, gives — is not `ok`, and neither
/// is a name the run never reported, which is what a renamed test would be.
fn differential_verdict(names: &[&str], exited_ok: bool, stdout: &str) -> Result<(), Vec<String>> {
    let mut wrong = Vec::new();
    for name in names {
        let prefix = format!("test {name} ... ");
        match stdout.lines().find_map(|l| l.strip_prefix(&prefix)) {
            Some("ok") => {}
            Some(other) => wrong.push(format!("{name}: {other}")),
            None => wrong.push(format!("{name}: not run")),
        }
    }
    if wrong.is_empty() && !exited_ok {
        wrong.push("cargo test exited non-zero".to_string());
    }
    if wrong.is_empty() {
        Ok(())
    } else {
        Err(wrong)
    }
}

/// Run [`SETTINGS_DIFFERENTIAL`] in `workspace_root`, each pair as one `cargo test` of its
/// one file with `--exact` and its two names, and judge each by [`differential_verdict`].
///
/// `KOTTON_NO_SYSTEMD_PARSER` is taken out of the run's environment: under it the build
/// scripts compile the four `#[ignore]`d, and a release reads no developer's declaration
/// (`systemds_parser_refusal`). Built with `--locked`, as the release is, and in the target
/// the release builds that server in ([`source_target`]), so the tests that held this tree
/// are this tree's.
fn settings_differential(workspace_root: &Path) -> Result<(), Vec<String>> {
    let mut wrong = Vec::new();
    for (source, file, names) in SETTINGS_DIFFERENTIAL {
        match differential_command(workspace_root, source, file, &names).output() {
            Err(e) => wrong.push(format!("{file}: could not start cargo: {e}")),
            Ok(out) => {
                let stdout = String::from_utf8_lossy(&out.stdout);
                print!("{stdout}");
                if let Err(w) = differential_verdict(&names, out.status.success(), &stdout) {
                    wrong.extend(w.into_iter().map(|w| format!("{file}: {w}")));
                }
            }
        }
    }
    if wrong.is_empty() {
        Ok(())
    } else {
        Err(wrong)
    }
}

/// One server's half of the settings differential: `file`'s `names`, exactly, built in that
/// server's release target.
fn differential_command(workspace_root: &Path, source: Source, file: &str, names: &[&str]) -> Command {
    let mut cargo = Command::new("cargo");
    cargo.args(["test", "--locked"]);
    match source {
        Source::Package(p) => cargo.args(["-p", p]),
        Source::Manifest(m) => cargo.args(["--manifest-path", m]),
    };
    cargo
        .arg("--target-dir")
        .arg(source_target(source))
        .args(["--test", file, "--", "--exact"])
        .args(names)
        .env_remove(systemds_parser::SKIP_VAR)
        .current_dir(workspace_root)
        .stderr(Stdio::inherit());
    cargo
}

/// A free port on loopback, TCP and UDP both.
fn free_port() -> Result<u16, String> {
    for _ in 0..20 {
        let tcp = std::net::TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
        let port = tcp.local_addr().map_err(|e| e.to_string())?.port();
        if std::net::UdpSocket::bind(("127.0.0.1", port)).is_ok() {
            return Ok(port);
        }
    }
    Err("no loopback port free for both TCP and UDP".into())
}

struct Running {
    child: Child,
    port: u16,
}

/// Set `edits` in the installed env file, as a person edits it: each `KEY=` line
/// replaced in place. A key the file does not have is an error, so the test cannot
/// set a variable the host's file would not carry.
fn edit_env(path: &Path, edits: &[(&str, String)]) -> Result<(), String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut out = String::new();
    let mut seen = Vec::new();
    for line in text.lines() {
        match edits.iter().find(|(k, _)| line.starts_with(&format!("{k}="))) {
            Some((k, v)) => {
                out.push_str(&format!("{k}={v}\n"));
                seen.push(*k);
            }
            None => {
                out.push_str(line);
                out.push('\n');
            }
        }
    }
    if let Some((k, _)) = edits.iter().find(|(k, _)| !seen.contains(k)) {
        return Err(format!("{} has no {k}= line to set", path.display()));
    }
    std::fs::write(path, out).map_err(|e| e.to_string())
}

/// Run the installed binary under `root` with its installed env file and nothing
/// else — `EnvironmentFile=` as the unit reads it — logging to `log`. With `uid`, it runs
/// through `setpriv` as that uid ([`as_uid`]), as the unit's `User=` would run it.
fn run_installed(root: &Path, server: &Server, log: &Path, uid: Option<u32>) -> Result<Child, String> {
    let env_file = root.join("etc/kotton").join(server.env());
    let text = std::fs::read_to_string(&env_file).map_err(|e| format!("{}: {e}", env_file.display()))?;
    let bin = root.join("usr/local/bin").join(server.binary);
    let mut cmd = match uid {
        Some(n) => {
            let mut c = clean(Command::new("setpriv"));
            c.args(as_uid(n)).arg(&bin);
            c
        }
        None => clean(Command::new(&bin)),
    };
    for (k, v) in env_pairs(&text).map_err(|e| format!("{}: {e}", env_file.display()))? {
        cmd.env(k, v);
    }
    let out = std::fs::File::create(log).map_err(|e| e.to_string())?;
    let err = out.try_clone().map_err(|e| e.to_string())?;
    cmd.stdin(Stdio::null())
        .stdout(out)
        .stderr(err)
        .spawn()
        .map_err(|e| format!("cannot run the installed {}: {e}", server.binary))
}

/// `setpriv`'s arguments for running as `uid`, its group the same number, with no other
/// groups and no way back up — what the unit's `User=`, `Group=` and
/// `NoNewPrivileges=yes` give the service.
fn as_uid(uid: u32) -> [String; 6] {
    [
        "--reuid".into(),
        uid.to_string(),
        "--regid".into(),
        uid.to_string(),
        "--clear-groups".into(),
        "--no-new-privs".into(),
    ]
}

/// A uid for the installed binaries to run as, when this runs as root and `setpriv` is
/// here: the first number from 64100 that no user and no group of this machine has, so
/// nothing on it is theirs and nothing is added to its user database. `None` otherwise.
fn service_uid() -> Option<u32> {
    let me = Command::new("id").arg("-u").output().ok()?;
    if String::from_utf8_lossy(&me.stdout).trim() != "0" {
        return None;
    }
    Command::new("setpriv").arg("--version").output().ok().filter(|o| o.status.success())?;
    (64_100..64_200u32).find(|n| {
        ["passwd", "group"].iter().all(|db| {
            Command::new("getent")
                .args([db, &n.to_string().as_str()])
                .stdout(Stdio::null())
                .status()
                .is_ok_and(|s| !s.success())
        })
    })
}

/// A directory the unit has systemd make: created, mode 0700, and — when the binary runs
/// as a uid of its own — that uid's.
fn service_dir(dir: &Path, uid: Option<u32>) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).map_err(|e| e.to_string())?;
        if let Some(n) = uid {
            // Everything in it too, as systemd's `StateDirectory=` makes it the service's at
            // each start. What install.sh's `create` made here is already this uid's — it ran
            // as it (`StandInSystem`), and `created_as_its_user` read that before this ran.
            chown_all(dir, n)?;
        }
    }
    #[cfg(not(unix))]
    let _ = uid;
    Ok(())
}

/// `dir` and everything under it, `uid`'s.
#[cfg(unix)]
fn chown_all(dir: &Path, uid: u32) -> Result<(), String> {
    std::os::unix::fs::chown(dir, Some(uid), Some(uid)).map_err(|e| format!("chown {}: {e}", dir.display()))?;
    if dir.is_dir() {
        for e in std::fs::read_dir(dir).map_err(|e| e.to_string())?.flatten() {
            chown_all(&e.path(), uid)?;
        }
    }
    Ok(())
}

/// That the running `child` holds `uid`, read from `/proc/<pid>/status` — every one of
/// its real, effective, saved and filesystem uids — so a `setpriv` that did not take is
/// not read as a service that did.
fn holds_uid(child: &Child, what: &str, uid: Option<u32>) -> Result<(), String> {
    let Some(n) = uid else { return Ok(()) };
    let status = std::fs::read_to_string(format!("/proc/{}/status", child.id()))
        .map_err(|e| format!("cannot read the running {what}'s /proc status: {e}"))?;
    let line = status.lines().find(|l| l.starts_with("Uid:")).unwrap_or("");
    let ids: Vec<&str> = line.split_whitespace().skip(1).collect();
    if ids.len() != 4 || ids.iter().any(|i| *i != n.to_string()) {
        return Err(format!("the running {what} is not uid {n}: {line}"));
    }
    println!("release-server-test: the running {what} is uid {n} — {line}");
    Ok(())
}

#[cfg(unix)]
fn owner(path: &Path) -> Result<u32, String> {
    use std::os::unix::fs::MetadataExt as _;
    Ok(std::fs::metadata(path).map_err(|e| format!("{}: {e}", path.display()))?.uid())
}

/// The relay's operator verb as the unit files say to type it at the host's shell — as
/// the relay's user, `runuser -u kotton-relay --`, here `setpriv` to its uid — writes the
/// operators' file into the state directory the running relay owns, and the file is that
/// user's, so the relay reads it at its next operator request.
fn operator_verb_as_the_relays_user(root: &Path, uid: u32) -> Result<(), String> {
    let state = root.join("var/lib/kotton-relay");
    let key = "ab".repeat(32);
    let out = clean(Command::new("setpriv"))
        .args(as_uid(uid))
        .arg(root.join("usr/local/bin").join(RELAY.binary))
        .arg("--state-dir")
        .arg(&state)
        .args(["operator", "enrol", &key])
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("cannot run kotton-relay operator enrol: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "`kotton-relay operator enrol`, run as the relay's uid, could not write its state directory:\n{}",
            release::said(&out)
        ));
    }
    #[cfg(unix)]
    {
        let file = state.join("operators");
        let got = owner(&file)?;
        if got != uid {
            return Err(format!("{} is uid {got}'s, not the relay's {uid}", file.display()));
        }
    }
    println!("release-server-test: `kotton-relay operator enrol`, run as the relay's uid {uid}, wrote an operators file the running relay owns");
    Ok(())
}

fn start_relay(root: &Path, scratch: &Path, uid: Option<u32>) -> Result<Running, String> {
    let port = free_port()?;
    let state = root.join("var/lib/kotton-relay");
    service_dir(&state, uid)?;
    edit_env(
        &root.join("etc/kotton").join(RELAY.env()),
        &[
            ("KOTTON_RELAY_BIND", format!("127.0.0.1:{port}")),
            ("KOTTON_RELAY_STUN_BIND", format!("127.0.0.1:{port}")),
            ("KOTTON_RELAY_STATE_DIR", state.display().to_string()),
        ],
    )?;
    let child = run_installed(root, &RELAY, &scratch.join("relay.log"), uid)?;
    println!("release-server-test: started the installed kotton-relay on 127.0.0.1:{port}");
    Ok(Running { child, port })
}

/// `GET /health` on loopback, retried for thirty seconds while the relay comes up.
fn health(port: u16) -> Result<String, String> {
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut last = String::new();
    while Instant::now() < deadline {
        match std::net::TcpStream::connect(("127.0.0.1", port)) {
            Ok(mut s) => {
                let _ = s.set_read_timeout(Some(Duration::from_secs(5)));
                let _ = s.write_all(b"GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
                let mut got = String::new();
                let _ = s.read_to_string(&mut got);
                if got.starts_with("HTTP/1.1 200") && got.contains("\"status\":\"ok\"") {
                    return Ok(got.rsplit("\r\n\r\n").next().unwrap_or("").trim().to_string());
                }
                last = got;
            }
            Err(e) => last = e.to_string(),
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    Err(format!("the relay did not answer /health with status ok in 30 s: {last}"))
}

/// Start the installed vault beside the relay on `relay_port` — which it does not
/// stand at, since nothing told it to — read its first log
/// line, and see it still running a second later.
fn start_vault(root: &Path, scratch: &Path, relay_port: u16, uid: Option<u32>) -> Result<(), String> {
    let base = root.join("var/lib/kotton-vault");
    let run = root.join("run/kotton-vault");
    for d in [&base, &run] {
        service_dir(d, uid)?;
    }
    let peer = free_port()?;
    let log = scratch.join("vault.log");
    let env = root.join("etc/kotton").join(VAULT.env());
    edit_env(
        &env,
        &[
            ("KOTTON_BASE_DIR", base.display().to_string()),
            ("XDG_RUNTIME_DIR", run.display().to_string()),
            ("KOTTON_PEER_LISTEN_PORT", peer.to_string()),
        ],
    )?;
    let mut child = run_installed(root, &VAULT, &log, uid)?;
    println!("release-server-test: started the installed kvaultd, peer port {peer}, beside the relay on {relay_port}");
    let outcome = (|| {
        let deadline = Instant::now() + Duration::from_secs(30);
        let first = loop {
            let text = std::fs::read_to_string(&log).unwrap_or_default();
            if let Some(line) = text.lines().find(|l| !l.trim().is_empty()) {
                break line.to_string();
            }
            if let Ok(Some(status)) = child.try_wait() {
                return Err(format!("kvaultd exited ({status}) before it logged a line"));
            }
            if Instant::now() > deadline {
                return Err("kvaultd logged nothing in 30 s".into());
            }
            std::thread::sleep(Duration::from_millis(100));
        };
        println!("release-server-test: kvaultd's first log line: {first}");
        // The first line is the secrets store it chose: the installed env file's
        // KOTTON_SECRETS=file, not a keychain the host does not have.
        if !first.contains("KOTTON_SECRETS=file") {
            return Err(format!("kvaultd's first line is not the file secrets store vault.env names: {first}"));
        }
        // And it came up: its door, its listener and its reservation at the relay.
        loop {
            let text = std::fs::read_to_string(&log).unwrap_or_default();
            if text.contains("relay reservation listener started") && text.contains("vault serving") {
                println!("release-server-test: kvaultd started its reservation at the relay and is serving");
                holds_uid(&child, "kvaultd", uid)?;
                break;
            }
            if let Ok(Some(status)) = child.try_wait() {
                return Err(format!("kvaultd exited ({status}):\n{text}"));
            }
            if Instant::now() > deadline {
                return Err(format!("kvaultd did not say it was serving in 30 s:\n{text}"));
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        // A verb typed bare at the host's shell finds the running vault's door: `kvaultd`
        // reads the vault.env installed beside it, as the unit hands it to the daemon.
        // The environment is a root login's — PATH and logind's XDG_RUNTIME_DIR, which
        // names a directory the door is not in — and nothing is sourced. `tenants`
        // changes nothing.
        let bin = root.join("usr/local/bin").join(VAULT.binary);
        verb_reaches(&bin, None, "root")?;
        // Run as root, the door is the vault's uid's, in a directory only it may enter,
        // and root's verb above reached it anyway: the door asks nothing of its caller.
        #[cfg(unix)]
        if let Some(n) = uid {
            // The door is where the vault put it, asked of the rule it asked, over the
            // env file it was started with: `$XDG_RUNTIME_DIR/kotton/vault.sock`, or a
            // short `/tmp` path when a long checkout makes that too long to bind. The
            // vault makes the directory either way 0700.
            let door = door(&env)?;
            let got = owner(&door)?;
            if got != n {
                return Err(format!("{} is uid {got}'s, not the vault's {n}", door.display()));
            }
            let dir = door.parent().ok_or_else(|| format!("{} has no directory", door.display()))?;
            let mode = {
                use std::os::unix::fs::PermissionsExt as _;
                std::fs::metadata(dir).map_err(|e| format!("{}: {e}", dir.display()))?.permissions().mode() & 0o777
            };
            if (owner(dir)?, mode) != (n, 0o700) {
                return Err(format!("{} is uid {}'s and {mode:o}, not the vault's {n} and 700", dir.display(), owner(dir)?));
            }
            println!("release-server-test: the door is uid {n}'s, in a 0700 directory of its own, and root's `kvaultd tenants` reached it");
            // And as the vault's own user, who reads vault.env through its group: install.sh's
            // `chgrp kotton-vault` gave the file to the uid's number (`StandInSystem`).
            verb_reaches(&bin, Some(n), "the vault's own uid")?;
        }
        Ok(())
    })();
    stop(&mut child);
    outcome?;
    // With the vault stopped, the same verb is refused in one sentence.
    let out = login_shell(&root.join("usr/local/bin").join(VAULT.binary), None)
        .arg("tenants")
        .output()
        .map_err(|e| format!("cannot run kvaultd tenants: {e}"))?;
    let said = String::from_utf8_lossy(&out.stderr);
    if out.status.code() != Some(1) || said.trim().lines().count() != 1 || !said.contains("no vault is running here") {
        return Err(format!("`kvaultd tenants` with no vault running was not refused in one sentence:\n{}", release::said(&out)));
    }
    println!("release-server-test: with the vault stopped, `kvaultd tenants` is refused: {}", said.trim());
    Ok(())
}

/// The socket the installed vault binds, found by the rule `kvaultd` finds it by
/// (`daemon_socket_path_in`) over the env file `run_installed` starts it with, and
/// nothing else — `EnvironmentFile=` as the unit reads it, `PATH` aside.
#[cfg(unix)]
fn door(env_file: &Path) -> Result<PathBuf, String> {
    let text = std::fs::read_to_string(env_file).map_err(|e| format!("{}: {e}", env_file.display()))?;
    let pairs = env_pairs(&text).map_err(|e| format!("{}: {e}", env_file.display()))?;
    // The last assignment wins, as it does when `run_installed` sets them in order.
    let env = |key: &str| pairs.iter().rev().find(|(k, _)| k == key).map(|(_, v)| v.clone());
    let name = env("KVAULTD_IPC_NAME").ok_or_else(|| format!("{} names no KVAULTD_IPC_NAME", env_file.display()))?;
    kotton_common::paths::daemon_socket_path_in(&env, &name).map_err(|e| e.to_string())
}

/// The installed `kvaultd` run as a person at the host's shell runs it: with `PATH` and a
/// login's `XDG_RUNTIME_DIR` and nothing else, as root or, with `uid`, as that uid.
fn login_shell(bin: &Path, uid: Option<u32>) -> Command {
    let mut c = match uid {
        Some(n) => {
            let mut c = clean(Command::new("setpriv"));
            c.args(as_uid(n)).arg(bin);
            c
        }
        None => clean(Command::new(bin)),
    };
    c.env("XDG_RUNTIME_DIR", format!("/run/user/{}", uid.unwrap_or(0)))
        .stdin(Stdio::null());
    c
}

/// `kvaultd tenants`, typed bare, reaches the running vault.
fn verb_reaches(bin: &Path, uid: Option<u32>, who: &str) -> Result<(), String> {
    let out = login_shell(bin, uid)
        .arg("tenants")
        .output()
        .map_err(|e| format!("cannot run kvaultd tenants: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "`kvaultd tenants`, typed bare as {who}, did not reach the running vault:\n{}",
            release::said(&out)
        ));
    }
    println!("release-server-test: `kvaultd tenants`, typed bare as {who} with only PATH and a login's XDG_RUNTIME_DIR, reached the running vault's door");
    Ok(())
}

fn stop(child: &mut Child) {
    #[cfg(unix)]
    {
        let _ = Command::new("kill").arg("-TERM").arg(child.id().to_string()).status();
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if let Ok(Some(_)) = child.try_wait() {
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }
    let _ = child.kill();
    let _ = child.wait();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn workspace() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().to_path_buf()
    }

    fn read(rel: &str) -> String {
        std::fs::read_to_string(workspace().join(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"))
    }

    /// The `--target-dir` a cargo command was handed.
    fn target_dir_of(cmd: &Command) -> PathBuf {
        let args: Vec<_> = cmd.get_args().map(|a| a.to_string_lossy().into_owned()).collect();
        let at = args.iter().position(|a| a == "--target-dir");
        at.and_then(|i| args.get(i + 1))
            .map(PathBuf::from)
            .unwrap_or_else(|| panic!("names no --target-dir: {args:?}"))
    }

    /// **Each server a release packs is built, tested and packed from a target only this
    /// checkout writes**, with `CARGO_TARGET_DIR` exported elsewhere: the relay under
    /// `out/release/relay`, the vault under `out/release/workspace`; the build, the settings
    /// differential's tests and the pack (which `--no-build` reads) all name that one.
    #[test]
    fn each_server_builds_in_a_target_of_its_own_under_an_exported_cargo_target_dir() {
        crate::out::exported::run(
            concat!(
                module_path!(),
                "::each_server_builds_in_a_target_of_its_own_under_an_exported_cargo_target_dir"
            ),
            |exported| {
                let root = crate::out::root();
                let out = root.join("out").join("release");
                assert_eq!(target_of(&RELAY), out.join("relay"));
                assert_eq!(target_of(&VAULT), out.join("workspace"));
                for server in SERVERS {
                    let mine = target_of(&server);
                    let what = format!("the {} release", server.name);
                    crate::out::exported::assert_private(&what, &mine, exported);
                    assert_eq!(target_dir_of(&build_command(&root, &server, TARGET)), mine, "{what}'s build");
                    assert!(built_binary(&server, TARGET).starts_with(&mine), "{what}'s pack reads where it built");
                    let (_, file, names) = SETTINGS_DIFFERENTIAL
                        .iter()
                        .find(|(s, _, _)| *s == server.source)
                        .unwrap_or_else(|| panic!("{what} has a settings differential"));
                    assert_eq!(
                        target_dir_of(&differential_command(&root, server.source, file, names)),
                        mine,
                        "{what}'s settings differential"
                    );
                }
            },
        );
    }

    /// The archive's name is `kotton-<name>-<rev>-linux-<arch>`, with the twelve
    /// characters `revision` takes, and one built off a release says so in its name.
    #[test]
    fn an_archive_is_named_for_its_server_commit_and_architecture() {
        assert_eq!(
            archive_name(RELAY.name, "8415af154deb", true, TARGET),
            "kotton-relay-8415af154deb-linux-x86_64"
        );
        assert_eq!(
            archive_name(VAULT.name, "8415af154deb", true, TARGET),
            "kotton-vault-8415af154deb-linux-x86_64"
        );
        assert_eq!(
            archive_name(VAULT.name, "8415af154deb", false, TARGET),
            "kotton-vault-8415af154deb-not-a-release-linux-x86_64"
        );
        assert_eq!(Server::of_archive(Path::new("dist/kotton-vault-x.tar.gz")), Some(VAULT));
        assert_eq!(Server::of_archive(Path::new("kotton-relay-x.tar.gz")), Some(RELAY));
        assert_eq!(Server::of_archive(Path::new("kotton-x.tar.gz")), None);
    }

    /// **Every build script that declares `kotton_no_systemd_parser` is its package's
    /// `build.rs`, at the package root.** The shared source
    /// (`infra/relay/tests/common/systemd_parser_cfg.rs`) is named by a path relative to the
    /// including build script, and handed to `rerun-if-changed`, which cargo resolves against
    /// the package root, beside `rerun-if-changed=build.rs`: the two agree only while the
    /// script is `<root>/build.rs`. Moved, or pointed elsewhere by a manifest's `build =` key,
    /// it still compiles and watches files that do not exist, so cargo reruns it on every build
    /// and nothing fails. Every consumer is found by what it calls, tracked or not, so a fourth
    /// is held without being listed here.
    #[test]
    fn the_systemd_parser_cfg_is_declared_only_by_a_build_rs_at_its_package_root() {
        // Split, so this file, which names the call, is not read as a consumer of it.
        const CALL: &str = concat!("declare_systemd_parser_cfg", "(shared!())");
        const SHARED: &str = "infra/relay/tests/common/systemd_parser_cfg.rs";
        let root = workspace();
        let shared = root.join(SHARED).canonicalize().unwrap();
        let listed = Command::new("git")
            .args(["ls-files", "-z", "--cached", "--others", "--exclude-standard", "--", "*.rs"])
            .current_dir(&root)
            .output()
            .unwrap();
        assert!(listed.status.success(), "git ls-files: {}", String::from_utf8_lossy(&listed.stderr));
        // `xtask/Cargo.toml` opens with a byte-order mark, which `trim` keeps.
        let is_package = |l: &str| l.trim_start_matches('\u{feff}').trim() == "[package]";
        let mut consumers = Vec::new();
        for rel in String::from_utf8(listed.stdout).unwrap().split('\0').filter(|r| !r.is_empty()) {
            let file = root.join(rel);
            let Ok(text) = std::fs::read_to_string(&file) else { continue };
            if !text.contains(CALL) {
                continue;
            }
            let package = file
                .ancestors()
                .skip(1)
                .find(|d| std::fs::read_to_string(d.join("Cargo.toml")).is_ok_and(|m| m.lines().any(is_package)))
                .unwrap_or_else(|| panic!("{rel}: no package above it"))
                .to_path_buf();
            let at = file.strip_prefix(&package).unwrap();
            assert_eq!(at, Path::new("build.rs"), "{rel} declares the cfg but is not its package's build.rs");
            let manifest = std::fs::read_to_string(package.join("Cargo.toml")).unwrap();
            let build_key: Vec<&str> = manifest
                .lines()
                .skip_while(|l| !is_package(l))
                .skip(1)
                .take_while(|l| !l.trim_start().starts_with('['))
                .filter(|l| l.trim_start().strip_prefix("build").is_some_and(|r| r.trim_start().starts_with('=')))
                .collect();
            assert!(
                build_key.iter().all(|l| l.split_once('=').unwrap().1.trim() == "\"build.rs\""),
                "{}: `build =` points away from build.rs: {build_key:?}",
                package.join("Cargo.toml").display()
            );
            let named = text
                .split_once("macro_rules! shared { () => { \"")
                .and_then(|(_, r)| r.split_once('"'))
                .unwrap_or_else(|| panic!("{rel}: no `shared!` naming the source"))
                .0;
            assert_eq!(
                package.join(named).canonicalize().ok().as_deref(),
                Some(shared.as_path()),
                "{rel}: `shared!` names {named}, which from its package root is not {SHARED}"
            );
            consumers.push(rel.to_string());
        }
        consumers.sort();
        for known in ["core/kvaultd/build.rs", "infra/relay/build.rs", "xtask/build.rs"] {
            assert!(consumers.iter().any(|c| c == known), "{known} was not found declaring the cfg: {consumers:?}");
        }
    }

    /// **No release is cut where systemd's parser is absent, and the skip variable does not
    /// change that.** The refusal names each missing half; a machine with both is not refused.
    #[test]
    fn a_release_is_refused_where_systemds_parser_is_absent() {
        use super::systemds_parser::find_in;
        let dir = tempfile::tempdir().unwrap();
        let empty = dir.path().join("empty");
        let lib = dir.path().join("lib");
        let bin = dir.path().join("bin");
        for d in [&empty, &lib, &bin] {
            std::fs::create_dir_all(d).unwrap();
        }
        std::fs::write(lib.join("libsystemd-shared-255.so"), b"").unwrap();
        std::fs::write(bin.join("python3"), b"").unwrap();

        let neither = systemds_parser_refusal(find_in(&[&empty], Some(empty.as_os_str()))).unwrap();
        assert!(neither.contains("no libsystemd-shared-*.so in") && neither.contains("no python3 on PATH"), "{neither}");
        assert!(neither.contains("KOTTON_NO_SYSTEMD_PARSER does not change that"), "{neither}");
        let no_python = systemds_parser_refusal(find_in(&[&lib], Some(empty.as_os_str()))).unwrap();
        assert!(no_python.contains("no python3") && !no_python.contains("libsystemd-shared-*.so"), "{no_python}");
        let no_library = systemds_parser_refusal(find_in(&[&empty], Some(bin.as_os_str()))).unwrap();
        assert!(no_library.contains("libsystemd-shared-*.so") && !no_library.contains("python3"), "{no_library}");
        assert_eq!(systemds_parser_refusal(find_in(&[&lib], Some(bin.as_os_str()))), None);
    }

    /// **A differential test that cannot reach systemd's parser fails naming what is
    /// missing, unless the run declared it; then it says `SKIPPED` and its name.** And a
    /// declaration never hides a parser that is there.
    #[test]
    fn a_differential_without_systemds_parser_fails_unless_the_run_declares_it() {
        use super::systemds_parser::{for_test, SystemdsParser, SKIP_VAR};
        let missing = || Err::<SystemdsParser, _>("no python3 on PATH".to_string());
        let failed = for_test("the_test", missing(), false).unwrap_err();
        assert!(failed.contains("the_test") && failed.contains("no python3 on PATH") && failed.contains(SKIP_VAR), "{failed}");
        let skipped = for_test("the_test", missing(), true).unwrap().unwrap_err();
        assert!(skipped.starts_with("SKIPPED the_test: no python3 on PATH"), "{skipped}");
        let found = SystemdsParser { library: "/l.so".into(), python: "/p".into() };
        assert_eq!(for_test("the_test", Ok(found.clone()), true), Ok(Ok(found)));
    }

    /// **The differential's verdict is `ok` by name, or it is not a comparison.** `ignored`,
    /// `FAILED`, a name the run never reported (a renamed test) and a non-zero exit with all
    /// four `ok` are each a refusal naming what it saw.
    #[test]
    fn the_differential_is_a_comparison_only_where_libtest_says_ok_of_each_by_name() {
        let names = ["a_test", "b_test"];
        let ok = "running 2 tests\ntest a_test ... ok\ntest b_test ... ok\n\ntest result: ok. 2 passed\n";
        assert_eq!(differential_verdict(&names, true, ok), Ok(()));
        let ignored = "test a_test ... ok\ntest b_test ... ignored, KOTTON_NO_SYSTEMD_PARSER is set: x\n";
        assert_eq!(
            differential_verdict(&names, true, ignored),
            Err(vec!["b_test: ignored, KOTTON_NO_SYSTEMD_PARSER is set: x".to_string()])
        );
        let failed = "test a_test ... FAILED\ntest b_test ... ok\n";
        assert_eq!(differential_verdict(&names, false, failed), Err(vec!["a_test: FAILED".to_string()]));
        let renamed = "test a_test ... ok\ntest b_test_renamed ... ok\n";
        assert_eq!(differential_verdict(&names, true, renamed), Err(vec!["b_test: not run".to_string()]));
        assert_eq!(
            differential_verdict(&names, false, ok),
            Err(vec!["cargo test exited non-zero".to_string()])
        );
        // The list the release runs is the four the corpus holds, two per crate.
        let all: Vec<&str> = SETTINGS_DIFFERENTIAL.iter().flat_map(|(_, _, n)| n.iter().copied()).collect();
        assert_eq!(all.len(), 4);
    }

    /// **What `release::box` refused, this refuses:** a HEAD that is not origin/main, a
    /// tree git does not hold, and a commit already released — whose sum it prints.
    #[test]
    fn a_commit_is_released_once_from_a_clean_main() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("kotton-relay-8415af154deb-linux-x86_64.tar.gz");
        let head = "8415af154deb7e55c7e5e3f8b901777cd7e9f9a7";
        let clean = Revision { sha: head[..12].into(), dirty: false };
        let dirty = Revision { sha: head[..12].into(), dirty: true };

        assert_eq!(refusal(&clean, Some(head), head, &archive), None);
        assert!(refusal(&clean, Some("b97a963"), head, &archive).unwrap().contains("origin/main is b97a963"));
        assert!(refusal(&clean, None, head, &archive).unwrap().contains("origin/main"));
        assert!(refusal(&dirty, Some(head), head, &archive).unwrap().contains("changes git does not hold"));

        std::fs::write(&archive, b"released").unwrap();
        let why = refusal(&clean, Some(head), head, &archive).unwrap();
        assert!(why.contains("already released"), "{why}");
        assert!(
            why.contains("kotton-relay-8415af154deb-linux-x86_64.tar.gz") && why.contains("  "),
            "{why}"
        );
    }

    /// **The units carry what the compose file carried.** Every variable the compose
    /// file's `environment:` blocks set for a service, and every one the vault's image
    /// set (`infra/Dockerfile`: `KOTTON_SECRETS`, `KVAULTD_IPC_NAME`, `XDG_RUNTIME_DIR`),
    /// is in that service's env file, with the compose file's default where it had one.
    #[test]
    fn the_env_files_carry_the_compose_files_environment() {
        let compose = read("infra/vault/docker-compose.yml");
        for (server, service, from_image) in [
            (RELAY, "relay", &[][..]),
            (VAULT, "vault", &["KOTTON_SECRETS", "KVAULTD_IPC_NAME", "XDG_RUNTIME_DIR"][..]),
        ] {
            let pairs = env_pairs(&read(server.env_src)).unwrap();
            let has = |k: &str| pairs.iter().find(|(key, _)| key == k).map(|(_, v)| v.clone());
            let block = compose
                .split(&format!("\n  {service}:\n"))
                .nth(1)
                .unwrap()
                .split("\n  vault:\n")
                .next()
                .unwrap();
            let env = block.split("environment:\n").nth(1).unwrap();
            let mut named = 0;
            for line in env.lines().take_while(|l| l.starts_with("      ") || l.trim().is_empty()) {
                let l = line.trim();
                if l.starts_with('#') || l.is_empty() {
                    continue;
                }
                let (key, value) = l.split_once(':').unwrap();
                named += 1;
                let got = has(key).unwrap_or_else(|| panic!("{}: {key} is in the compose file and not here", server.env_src));
                // `"${X:-default}"` → default; a literal is itself.
                let value = value.trim().trim_matches('"');
                let default = match value.strip_prefix("${").and_then(|v| v.strip_suffix('}')) {
                    Some(inner) => inner.split_once(":-").map(|(_, d)| d.to_string()),
                    None => Some(value.to_string()),
                };
                match (key, default) {
                    // Paths inside the container become the host's: the state
                    // directories under /var/lib/ the units name.
                    ("KOTTON_RELAY_STATE_DIR", _) => assert_eq!(got, "/var/lib/kotton-relay"),
                    ("KOTTON_BASE_DIR", _) => assert_eq!(got, "/var/lib/kotton-vault"),
                    (_, Some(d)) if !d.contains("${") => assert_eq!(got, d, "{key}"),
                    _ => {}
                }
            }
            assert!(named >= 3, "{service}: read {named} variables — did the compose file move?");
            for key in from_image {
                assert!(has(key).is_some(), "{}: {key}, which the image set, is not here", server.env_src);
            }
        }
    }

    /// **Each unit reads its env file, restarts on failure, and keeps its state under
    /// /var/lib/**, and runs the binary install.sh places.
    #[test]
    fn each_unit_reads_its_env_file_restarts_and_keeps_state_under_var_lib() {
        for server in SERVERS {
            let unit = read(server.unit_src);
            let has = |line: &str| unit.lines().any(|l| l.trim() == line);
            assert!(has(&format!("EnvironmentFile=/etc/kotton/{}", server.env())), "{}", server.unit_src);
            assert!(has(&format!("ExecStart=/usr/local/bin/{}", server.binary)), "{}", server.unit_src);
            assert!(has("Restart=on-failure"), "{}", server.unit_src);
            assert!(has(&format!("StateDirectory=kotton-{}", server.name)), "{}", server.unit_src);
            assert!(has("WantedBy=multi-user.target"), "{}", server.unit_src);
            // The env file's state directory is the one systemd makes.
            let state = env_pairs(&read(server.env_src)).unwrap()
                .into_iter()
                .find(|(k, _)| k == "KOTTON_RELAY_STATE_DIR" || k == "KOTTON_BASE_DIR")
                .unwrap()
                .1;
            assert_eq!(state, format!("/var/lib/kotton-{}", server.name));
        }
        // The vault's socket directory is the one its unit makes, and the one vault.env
        // names — to the daemon, and to a verb that reads the file beside it.
        assert!(read(VAULT.unit_src).lines().any(|l| l == "RuntimeDirectory=kotton-vault"));
        assert!(env_pairs(&read(VAULT.env_src)).unwrap().contains(&("XDG_RUNTIME_DIR".into(), "/run/kotton-vault".into())));
    }

    /// **The install test looks for the vault's door where the vault put it**, in a
    /// scratch host at any depth. The host is laid out as `start_vault` lays it out, with
    /// the shipped vault.env edited as it edits it, under a directory deep enough that
    /// `run/kotton-vault/kotton/vault.sock` is over 103 bytes — the depth a checkout at
    /// `.claude/worktrees/<name>` gives `out/dist/.ksrv-vault-<pid>/host`. The kernel,
    /// not a constant, says the joined path is no door: binding it fails. The path
    /// `door` names binds, and it is not the joined one. At a short root the two are the
    /// same path, so a host keeps `/run/kotton-vault/kotton/vault.sock`
    /// (`TASK-release-server-test-looks-for-the-vaults-door-where-a-long-checkout-path-does-not-put-it`).
    #[cfg(unix)]
    #[test]
    fn the_door_is_found_where_the_vault_binds_it_at_any_depth() {
        use std::os::unix::net::UnixListener;
        let scratch = tempfile::tempdir().unwrap();
        let installed = |root: &Path| {
            let run = root.join("run/kotton-vault");
            std::fs::create_dir_all(&run).unwrap();
            std::fs::create_dir_all(root.join("etc/kotton")).unwrap();
            let env = root.join("etc/kotton").join(VAULT.env());
            std::fs::copy(workspace().join(VAULT.env_src), &env).unwrap();
            edit_env(
                &env,
                &[
                    ("KOTTON_BASE_DIR", root.join("var/lib/kotton-vault").display().to_string()),
                    ("XDG_RUNTIME_DIR", run.display().to_string()),
                ],
            )
            .unwrap();
            (env, run.join("kotton").join("vault.sock"))
        };

        // Deep: over 103 bytes joined, which no bind accepts.
        let deep = scratch.path().join("a".repeat(60)).join("host");
        let (env, joined) = installed(&deep);
        assert!(joined.as_os_str().len() > 103, "{} is not deep enough", joined.display());
        std::fs::create_dir_all(joined.parent().unwrap()).unwrap();
        assert!(UnixListener::bind(&joined).is_err(), "{} bound; the scratch is not deep enough", joined.display());
        let found = door(&env).unwrap();
        assert_ne!(found, joined, "the door was joined by hand");
        std::fs::create_dir_all(found.parent().unwrap()).unwrap();
        let bound = UnixListener::bind(&found);
        let _ = std::fs::remove_dir_all(found.parent().unwrap());
        bound.unwrap_or_else(|e| panic!("{} does not bind: {e}", found.display()));

        // Shallow: the joined path, as on a host.
        let (env, joined) = installed(&scratch.path().join("b"));
        assert!(joined.as_os_str().len() <= 103, "{}", joined.display());
        assert_eq!(door(&env).unwrap(), joined);
    }

    /// **The test reads the env file in the one plain form the installer, systemd and
    /// `kvaultd` read**: a value a person quoted is the value without its quotes, and a line
    /// in another form is refused naming it, never trimmed into a setting
    /// (`TASK-release-server-tests-reader-of-the-env-file-is-not-the-plain-form`).
    #[cfg(unix)]
    #[test]
    fn the_door_is_read_from_a_quoted_value_without_its_quotes_and_another_form_is_refused() {
        let scratch = tempfile::tempdir().unwrap();
        let run = scratch.path().join("run/kotton-vault");
        let joined = run.join("kotton").join("vault.sock");
        let shipped = read(VAULT.env_src);
        let written = |name: &str, line: String| {
            let env = scratch.path().join(name);
            let text = shipped.replace("XDG_RUNTIME_DIR=/run/kotton-vault\n", &format!("{line}\n"));
            assert_ne!(text, shipped, "the shipped vault.env sets XDG_RUNTIME_DIR=/run/kotton-vault");
            std::fs::write(&env, text).unwrap();
            env
        };
        for line in [
            format!("XDG_RUNTIME_DIR={}", run.display()),
            format!("XDG_RUNTIME_DIR=\"{}\"", run.display()),
            format!("XDG_RUNTIME_DIR='{}'", run.display()),
        ] {
            assert_eq!(door(&written("quoted.env", line.clone())).unwrap(), joined, "{line}");
        }
        for line in [
            format!("XDG_RUNTIME_DIR = {}", run.display()),
            format!("  XDG_RUNTIME_DIR={}", run.display()),
            format!("XDG_RUNTIME_DIR={} ", run.display()),
            format!("export XDG_RUNTIME_DIR={}", run.display()),
        ] {
            let why = door(&written("other.env", line.clone())).expect_err(&line);
            assert!(why.contains("not in the plain form"), "{line}: {why}");
        }
    }

    /// **Each unit runs its binary as a user of its own**, `kotton-<name>` for both
    /// `User=` and `Group=`, and keeps the confinement it had as root: the lines the
    /// record names, and its directories 0700 — now that user's
    /// (`TASK-the-relay-and-the-vault-run-as-root-on-a-box`).
    #[test]
    fn each_unit_runs_as_a_user_of_its_own_and_keeps_its_confinement() {
        for server in SERVERS {
            let unit = read(server.unit_src);
            let user = format!("kotton-{}", server.name);
            assert_eq!(unit_value(&unit, "User").as_deref(), Some(user.as_str()), "{}", server.unit_src);
            assert_eq!(unit_value(&unit, "Group").as_deref(), Some(user.as_str()), "{}", server.unit_src);
            // A user install.sh makes, not one systemd invents per start: the verbs at
            // the host's shell name it, and a state directory under DynamicUser= moves.
            assert_eq!(unit_value(&unit, "DynamicUser"), None, "{}", server.unit_src);
            for (key, value) in [
                ("NoNewPrivileges", "yes"),
                ("ProtectSystem", "strict"),
                ("ProtectHome", "yes"),
                ("PrivateTmp", "yes"),
                ("UMask", "0077"),
                ("StateDirectoryMode", "0700"),
            ] {
                assert_eq!(unit_value(&unit, key).as_deref(), Some(value), "{}: {key}", server.unit_src);
            }
        }
        assert_eq!(unit_value(&read(VAULT.unit_src), "RuntimeDirectoryMode").as_deref(), Some("0700"));
        // The last of a key said twice wins, as systemd reads it, and only [Service]
        // is the service's. Every other spelling is refused by `unit_normal_form`.
        let service = |body: &str| format!("[Unit]\nUser=nobody\n[Service]\n{body}");
        let user = |body: &str| unit_value(&service(body), "User");
        assert_eq!(user("User=root\nUser=kotton-relay\n").as_deref(), Some("kotton-relay"));
        assert_eq!(user("# User=root\nUser=kotton-relay\n").as_deref(), Some("kotton-relay"));
        assert_eq!(unit_value("User=root\n", "User"), None, "outside any section is not the service's");
    }

    /// **Each unit is written in the one form it is read in** (`unit_normal_form`), and
    /// every spelling systemd reads that a line-by-line reader could read another way is
    /// refused, naming its line: each was once a green test over a weaker unit.
    #[test]
    fn each_unit_is_written_in_the_one_form_it_is_read_in() {
        for server in SERVERS {
            if let Err(e) = unit_normal_form(&read(server.unit_src), server.own_service_keys) {
                panic!("{}: {e}", server.unit_src);
            }
        }
        let good = "# a comment\n[Unit]\nDescription=x\n\n[Service]\nUser=a\nCapabilityBoundingSet=\nSystemCallFilter=@system-service\nSystemCallFilter=~@privileged\n[Install]\nWantedBy=multi-user.target\n";
        assert_eq!(unit_normal_form(good, &[]), Ok(()));
        let with = |line: &str| good.replace("User=a\n", &format!("User=a\n{line}\n"));
        for (bad, why) in [
            (with("ProtectClock = no"), "whitespace around ="),
            (with("SystemCallFilter ="), "whitespace before ="),
            (with("ProtectClock= no"), "whitespace after ="),
            (with(" ProtectClock=no"), "a leading space"),
            (with("ProtectClock=yes "), "a trailing space"),
            (with("ProtectClock=\u{b}yes"), "a vertical tab"),
            (with("EnvironmentFile=/a \\"), "a continuation"),
            (with("EnvironmentFile=/a\\\\"), "an escaped backslash at the end"),
            (with("Description=x\rProtectClock=no"), "a lone carriage return"),
            (with("[X-Kotton]"), "an X- section"),
            (with("; ProtectClock=no"), "a ; comment"),
            (with("User=root"), "a key said twice"),
            (format!("\u{feff}{good}"), "a byte-order mark"),
            (with("# c\0SystemCallFilter="), "a NUL in a comment, which systemd ends the line at"),
            (with("# c\rUser=root"), "a CR in a comment"),
            (with("# c\tx"), "a tab in a comment"),
            (with("# a comment \\"), "a comment ending in a backslash"),
            (with(&format!("#{}", "a".repeat(2 << 20))), "a 2 MiB comment, which systemd refuses the unit for"),
            (with(&format!("Description={}", "a".repeat(UNIT_LINE_MAX))), "a line one byte over the bound"),
            (good.replace("[Service]\n", "[Service] # x\n"), "a comment after a header"),
            (good.replace("[Install]\nWantedBy=multi-user.target\n", ""), "no [Install]"),
        ] {
            // Refused for its spelling, not because the key happens to be one the form
            // does not name: that refusal is the next test's.
            match unit_normal_form(&bad, &[]) {
                Ok(()) => panic!("{why} was not refused:\n{bad}"),
                Err(e) => assert!(!e.contains(NOT_NAMED), "{why} was refused only for its key: {e}"),
            }
        }
    }

    /// What `unit_normal_form` says of a key it does not name for the section.
    const NOT_NAMED: &str = "is not a key the normal form names";

    /// **A key the normal form does not name is refused, naming its line**, however
    /// cleanly it is spelled: added to either shipped unit's `[Service]`, `ExecStartPre=+`
    /// — a command run with full privileges outside every directive, which
    /// `systemd-analyze` does not score — and `AmbientCapabilities=` are each refused, as
    /// is a key named for another section
    /// (`TASK-a-service-key-the-normal-form-does-not-name-passes-both-unit-tests`).
    #[test]
    fn a_key_the_normal_form_does_not_name_is_refused_at_its_line() {
        for server in SERVERS {
            let unit = read(server.unit_src);
            let install = unit.lines().position(|l| l == "[Install]").expect("an [Install] line");
            // Each line goes in as the last of [Service], so it is line `install + 1`.
            for line in [
                "ExecStartPre=+/bin/true",
                "AmbientCapabilities=CAP_SYS_ADMIN",
                "PermissionsStartOnly=yes",
                "Description=a [Unit] key in [Service]",
                "Environment=A=1",
            ] {
                let bad = unit.replacen("\n[Install]\n", &format!("\n{line}\n[Install]\n"), 1);
                let e = unit_normal_form(&bad, server.own_service_keys).expect_err(&format!("{}: `{line}` was not refused", server.unit_src));
                let at = format!("line {}: {}= {NOT_NAMED}", install + 1, line.split_once('=').unwrap().0);
                assert!(e.starts_with(&at), "{}: `{line}`: {e}", server.unit_src);
            }
            // A key only the other unit says: the relay's `RuntimeDirectory=kotton-vault`
            // would make the vault's door's directory the relay's
            // (TASK-the-normal-form-lets-the-relay-say-a-key-only-the-vault-needs).
            for other in SERVERS.iter().filter(|o| o.name != server.name) {
                for key in other.own_service_keys.iter().filter(|k| !server.own_service_keys.contains(k)) {
                    let line = format!("{key}=kotton-{}", other.name);
                    let bad = unit.replacen("\n[Install]\n", &format!("\n{line}\n[Install]\n"), 1);
                    let e = unit_normal_form(&bad, server.own_service_keys)
                        .expect_err(&format!("{}: `{line}`, the {}'s key, was not refused", server.unit_src, other.name));
                    assert!(e.starts_with(&format!("line {}: {key}= {NOT_NAMED}", install + 1)), "{}: `{line}`: {e}", server.unit_src);
                }
            }
            // A [Service] key in [Install], and an [Install] key in [Unit].
            for (after, line) in [("[Install]", "User=root"), ("[Unit]", "WantedBy=multi-user.target")] {
                let bad = unit.replacen(&format!("\n{after}\n"), &format!("\n{after}\n{line}\n"), 1);
                let e = unit_normal_form(&bad, server.own_service_keys).expect_err(&format!("{}: `{line}` after {after}", server.unit_src));
                assert!(e.contains(NOT_NAMED), "{}: `{line}` after {after}: {e}", server.unit_src);
            }
        }
    }

    /// **Every key the normal form names is one a shipped unit says**, in that section:
    /// a key in [`UNIT_KEYS`] is said by every unit, and a unit's `own_service_keys` by that
    /// unit and not in [`UNIT_KEYS`]. The lists are the smallest the units need, so neither
    /// grows into a list of keys systemd reads, and a key one unit needs does not become
    /// one the other may say.
    #[test]
    fn every_key_the_normal_form_names_is_one_a_unit_says() {
        let says = |unit: &str, section: &str, key: &str| {
            let mut here = false;
            unit.lines().any(|l| {
                if l.starts_with('[') {
                    here = l == section;
                }
                here && l.split_once('=').is_some_and(|(k, _)| k == key)
            })
        };
        for server in SERVERS {
            let unit = read(server.unit_src);
            for (section, keys) in UNIT_SECTIONS.iter().zip(UNIT_KEYS) {
                for key in keys {
                    assert!(says(&unit, section, key), "{key}= is named for {section}, and {} does not say it there", server.unit_src);
                }
            }
            for key in server.own_service_keys {
                assert!(!UNIT_KEYS[1].contains(key), "{key}= is {}'s own and also named for both", server.name);
                assert!(says(&unit, "[Service]", key), "{key}= is {}'s own, and {} does not say it", server.name, server.unit_src);
            }
        }
    }

    /// **Each unit takes away what its binary never reaches for**, line by line: the
    /// directives run under systemd 255 on Ubuntu 24.04 with the relay answering
    /// `/health`, the vault serving at it and `kvaultd tenants` reaching its door
    /// (`TASK-the-relay-and-the-vault-units-are-still-rated-exposed`). The address
    /// families are each binary's own — the vault's door is `AF_UNIX`, the relay has
    /// none — and neither has `AF_NETLINK`.
    #[test]
    fn each_unit_takes_away_what_its_binary_never_reaches_for() {
        for server in SERVERS {
            let unit = read(server.unit_src);
            let has = |line: &str| unit.lines().any(|l| l.trim() == line);
            // What is in force, not only what is present: systemd takes the last of a
            // key said twice, so a later `ProtectClock=no` undoes the line above it.
            for (key, value) in [
                ("PrivateDevices", "yes"),
                ("ProtectKernelTunables", "yes"),
                ("ProtectKernelModules", "yes"),
                ("ProtectKernelLogs", "yes"),
                ("ProtectControlGroups", "yes"),
                ("ProtectClock", "yes"),
                ("ProtectHostname", "yes"),
                ("RestrictSUIDSGID", "yes"),
                ("RestrictNamespaces", "yes"),
                ("LockPersonality", "yes"),
                ("SystemCallArchitectures", "native"),
                ("SystemCallErrorNumber", "EPERM"),
                // The six of the ten that the next record found unset and that each
                // binary never reaches for: traced outside systemd, not yet run under it
                // (TASK-the-relay-and-the-vault-units-leave-ten-directives-unset-that-nobody-has-run).
                ("RemoveIPC", "yes"),
                ("MemoryDenyWriteExecute", "yes"),
                ("RestrictRealtime", "yes"),
                ("ProtectProc", "invisible"),
                ("ProcSubset", "pid"),
                ("PrivateUsers", "yes"),
            ] {
                assert_eq!(unit_value(&unit, key).as_deref(), Some(value), "{}: {key}", server.unit_src);
            }
            // SystemCallFilter= accumulates, and a bare `SystemCallFilter=` empties it,
            // so the filter is its two lines in order and nothing else under that key.
            // The unit is in `unit_normal_form`, so every such line is read.
            assert_eq!(
                unit_values(&unit, "SystemCallFilter"),
                ["@system-service", "~@privileged @resources"],
                "{}",
                server.unit_src
            );
            for line in [
                "CapabilityBoundingSet=",
                "PrivateDevices=yes",
                "ProtectKernelTunables=yes",
                "ProtectKernelModules=yes",
                "ProtectKernelLogs=yes",
                "ProtectControlGroups=yes",
                "ProtectClock=yes",
                "ProtectHostname=yes",
                "RestrictSUIDSGID=yes",
                "RestrictNamespaces=yes",
                "LockPersonality=yes",
                "SystemCallArchitectures=native",
                "SystemCallFilter=@system-service",
                "SystemCallFilter=~@privileged @resources",
                "SystemCallErrorNumber=EPERM",
            ] {
                assert!(has(line), "{}: `{line}` is missing", server.unit_src);
            }
            // Said once: a second CapabilityBoundingSet= or RestrictAddressFamilies=
            // line adds to the first, so the one line is the whole set.
            assert_eq!(unit_values(&unit, "CapabilityBoundingSet"), [""], "{}", server.unit_src);
            let n = unit_values(&unit, "RestrictAddressFamilies").len();
            assert_eq!(n, 1, "{}: RestrictAddressFamilies= said {n} times", server.unit_src);
            let families = match server.name {
                "relay" => "AF_INET AF_INET6",
                "vault" => "AF_UNIX AF_INET AF_INET6",
                other => panic!("{other}: which families does it open? Trace it under systemd first"),
            };
            assert_eq!(unit_value(&unit, "RestrictAddressFamilies").as_deref(), Some(families), "{}", server.unit_src);
        }
    }

    /// **The relay's operator verbs are typed as root or as the relay's user**, wherever
    /// the relay's README and its unit write them: they write the state
    /// directory the running relay owns and give what they write to its owner, so either
    /// typist leaves a file the relay reads
    /// (`TASK-a-relay-operator-verb-typed-as-root-locks-every-operator-out-until-the-relay-restarts`).
    /// A verb line typed as any other user is refused — it reads and writes nothing. The
    /// vault's verbs stay root's: they only speak to its door.
    ///
    /// Each file read must carry a verb line. A guide the verb moves out of leaves the list —
    /// `run-a-vault.md` did when DEC-0087 split the guides — rather than being exempted, so a
    /// file on the list is always one the owner types the verb from
    /// (`TASK-the-relay-operator-verb-test-reads-the-vault-guide-the-verb-moved-out-of`).
    #[test]
    fn the_relays_operator_verbs_are_typed_as_its_user() {
        let user = unit_value(&read(RELAY.unit_src), "User").unwrap().to_string();
        for doc in ["infra/relay/README.md", RELAY.unit_src] {
            let verbs = relay_operator_verbs(&read(doc));
            assert!(!verbs.is_empty(), "{doc}: no relay operator verb found — did it move?");
            for v in verbs {
                assert!(typed_as_root_or(&v, &user), "{doc}: `{v}` is not typed as root or {user}");
            }
        }
        // Root may type it through sudo, as the operator-verb record's own example does.
        let sudo = "sudo kotton-relay --state-dir /var/lib/kotton-relay operator enrol <key>";
        assert!(typed_as_root_or(sudo, &user), "`{sudo}` is typed as root");
        // The refusal still fires: a verb line typed as anyone else is not either form.
        for planted in [
            "runuser -u nobody -- kotton-relay --state-dir /var/lib/kotton-relay operator enrol <key>",
            "sudo -u nobody kotton-relay --state-dir /var/lib/kotton-relay operator enrol <key>",
            "runuser -u kotton-relay-x -- kotton-relay --state-dir /var/lib/kotton-relay operator enrol <key>",
        ] {
            let verbs = relay_operator_verbs(planted);
            assert_eq!(verbs.len(), 1, "`{planted}` is not read as a verb line");
            assert!(!typed_as_root_or(&verbs[0], &user), "`{planted}` was accepted");
        }
    }

    /// The relay operator verb lines of `text`, a leading `#` (a unit comment) stripped.
    fn relay_operator_verbs(text: &str) -> Vec<String> {
        text.lines()
            .map(|l| l.trim_start_matches('#').trim())
            .filter(|l| l.contains("kotton-relay --state-dir") && l.contains(" operator "))
            .map(str::to_string)
            .collect()
    }

    /// Whether a verb line is typed as root — bare at the host's shell, or through a plain
    /// `sudo` — or as `user`.
    fn typed_as_root_or(verb: &str, user: &str) -> bool {
        let bare = "kotton-relay --state-dir /var/lib/kotton-relay operator ";
        [String::new(), "sudo ".into(), format!("runuser -u {user} -- ")]
            .iter()
            .any(|typist| verb.strip_prefix(typist.as_str()).is_some_and(|rest| rest.starts_with(bare)))
    }

    /// **The ports are unchanged:** each port the env files listen on publicly is one the
    /// compose files publish (`port-check` holds those to one host), and the relay's STUN
    /// stays on loopback, as the compose file (which never published it) left it.
    #[test]
    fn the_env_files_listen_on_the_composed_ports() {
        let table: Vec<(u16, bool)> = ["infra/relay", "infra/vault"]
            .iter()
            .flat_map(|dir| crate::port_check::published_in(&read(&format!("{dir}/docker-compose.yml")), dir))
            .map(|p| (p.port, p.udp))
            .collect();
        let relay = env_pairs(&read(RELAY.env_src)).unwrap();
        let get = |pairs: &[(String, String)], k: &str| pairs.iter().find(|(key, _)| key == k).unwrap().1.clone();
        assert_eq!(get(&relay, "KOTTON_RELAY_BIND"), "0.0.0.0:7700");
        assert!(table.contains(&(7700, false)));
        assert!(get(&relay, "KOTTON_RELAY_STUN_BIND").starts_with("127.0.0.1:"));
        let vault = env_pairs(&read(VAULT.env_src)).unwrap();
        let port: u16 = get(&vault, "KOTTON_PEER_LISTEN_PORT").parse().unwrap();
        assert!(table.contains(&(port, true)), "7710/udp is the vault's row");
    }

    /// **install.sh makes the unit's user, places the three, refuses a file SHA256SUMS
    /// does not match, never overwrites the env file (root's, 0600: systemd reads it as
    /// root, and the service's user never opens it), and writes the one address when
    /// given it.** Run on a packed
    /// tree with a stand-in binary and a stand-in user database, since what is under
    /// test is the script.
    #[cfg(unix)]
    #[test]
    fn install_sh_checks_the_sums_places_the_files_and_keeps_the_settings() {
        let dir = tempfile::tempdir().unwrap();
        let tree = dir.path().join("kotton-vault-abc-linux-x86_64");
        std::fs::create_dir_all(tree.join("bin")).unwrap();
        std::fs::write(tree.join("bin/kvaultd"), b"#!/bin/sh\necho stand-in\n").unwrap();
        for (src, dst) in [
            (VAULT.unit_src, VAULT.unit()),
            (VAULT.env_src, VAULT.env()),
            (INSTALLER, "install.sh".to_string()),
        ] {
            std::fs::copy(workspace().join(src), tree.join(dst)).unwrap();
        }
        std::fs::write(tree.join("REVISION"), "abc\nbuilt for x86_64-unknown-linux-musl\n").unwrap();
        std::fs::write(tree.join(crate::license_check::FILE), "stand-in notices\n").unwrap();
        for f in release::OWN {
            std::fs::copy(workspace().join(f), tree.join(f)).unwrap();
        }
        let summed: Vec<String> = VAULT.entries().into_iter().filter(|e| e != "SHA256SUMS").collect();
        std::fs::write(tree.join("SHA256SUMS"), sum_lines(&tree, &summed).unwrap()).unwrap();

        // As root, with the user database stood in for: nothing is made on this machine.
        let system = StandInSystem::new(&dir.path().join("system"), 0, None).unwrap();
        let install = |system: &StandInSystem, root: Option<&Path>, addr: Option<&str>| {
            let mut c = system.command("/bin/sh");
            c.arg(tree.join("install.sh"));
            if let Some(r) = root {
                c.env("KOTTON_ROOT", r);
            }
            if let Some(a) = addr {
                c.env("KOTTON_PUBLIC_ADDR", a);
            }
            c.output().unwrap()
        };
        let user = unit_value(&read(VAULT.unit_src), "User").unwrap().to_string();

        // A clean install, with the host's address.
        let root = dir.path().join("root");
        let out = install(&system, Some(&root), Some("203.0.113.7"));
        assert!(out.status.success(), "{}", release::said(&out));
        let said = String::from_utf8_lossy(&out.stdout);
        assert!(said.contains("systemctl daemon-reload") && said.contains("systemctl enable --now kotton-vault"), "{said}");
        assert!(said.contains(&format!("user {user} (made now)")), "{said}");
        assert!(root.join("usr/local/bin/kvaultd").exists());
        assert!(root.join("etc/systemd/system/kotton-vault.service").exists());
        let env = root.join("etc/kotton/vault.env");
        // The unit's user is made, once.
        let asked = system.asked();
        assert_eq!(
            asked.lines().filter(|l| l.starts_with("useradd ")).collect::<Vec<_>>(),
            vec![useradd_line(&user, "vault")],
            "{asked}"
        );
        // Its env file is the vault's user's group's to read: `kvaultd`'s verbs read it.
        assert_eq!(file_mode(&env).unwrap(), 0o640);
        assert!(asked.lines().any(|l| l == format!("chgrp {user} {}", env.display())), "{asked}");
        let pairs = env_pairs(&std::fs::read_to_string(&env).unwrap()).unwrap();
        assert!(pairs.contains(&("KOTTON_PUBLIC_ADDR".into(), "203.0.113.7".into())));
        assert!(!pairs.iter().any(|(k, _)| k == "KOTTON_RELAY_URL"), "the installer names a relay: {pairs:?}");

        // An upgrade keeps what the person set and makes no second user.
        std::fs::write(&env, "KOTTON_PUBLIC_ADDR=edited\n").unwrap();
        let out = install(&system, Some(&root), Some("198.51.100.1"));
        assert!(out.status.success(), "{}", release::said(&out));
        assert!(String::from_utf8_lossy(&out.stdout).contains(&format!("user {user} (already on this host)")));
        assert_eq!(std::fs::read_to_string(&env).unwrap(), "KOTTON_PUBLIC_ADDR=edited\n");
        let asked = system.asked();
        assert_eq!(asked.lines().filter(|l| l.starts_with("useradd ")).count(), 1, "{asked}");
        assert_eq!(file_mode(&env).unwrap(), 0o640);
        assert_eq!(asked.lines().filter(|l| l.starts_with("chgrp ")).count(), 2, "set at every install: {asked}");

        // A group of the user's name the host already had, with members of its own, is not
        // handed the file: it stays root's alone, and the install says why.
        let crowded = StandInSystem::new(&dir.path().join("crowded"), 0, None).unwrap();
        std::fs::write(crowded.dir.join("groups"), format!("{user}:x:999:alice,bob\n")).unwrap();
        let croot = dir.path().join("croot");
        let out = install(&crowded, Some(&croot), None);
        assert!(out.status.success(), "{}", release::said(&out));
        assert!(String::from_utf8_lossy(&out.stdout).contains("has other members (alice,bob)"), "{}", release::said(&out));
        assert_eq!(file_mode(&croot.join("etc/kotton/vault.env")).unwrap(), 0o600);
        assert!(!crowded.asked().contains("chgrp"), "{}", crowded.asked());

        // An address that would make a wrong URL is refused.
        let out = install(&system, Some(&dir.path().join("elsewhere")), Some("2001:db8::1"));
        assert!(!out.status.success());

        // From an ssh session with no terminal, not given the address: the one the
        // session arrived at is proposed, the line that writes it printed, and nothing
        // written for it. Running that line then fills the still-empty value in the
        // kept file; a value a person set is never replaced, and not proposed over.
        let over_ssh = |root: &Path, arrived: &str, addr: Option<&str>| {
            let mut c = system.command("/bin/sh");
            c.arg(tree.join("install.sh"))
                .env("KOTTON_ROOT", root)
                .env("SSH_CONNECTION", format!("203.0.113.40 52814 {arrived} 22"))
                .stdin(Stdio::null());
            if let Some(a) = addr {
                c.env("KOTTON_PUBLIC_ADDR", a);
            }
            let out = c.output().unwrap();
            assert!(out.status.success(), "{}", release::said(&out));
            String::from_utf8_lossy(&out.stdout).to_string()
        };
        let sshroot = dir.path().join("sshroot");
        let senv = sshroot.join("etc/kotton/vault.env");
        let said = over_ssh(&sshroot, "198.51.100.7", None);
        let line = format!("KOTTON_PUBLIC_ADDR=198.51.100.7 sh '{}'", tree.join("install.sh").display());
        assert!(said.lines().any(|l| l.trim() == line), "{said}");
        assert!(!said.contains("private") && !said.contains("loopback"), "{said}");
        let pairs = env_pairs(&std::fs::read_to_string(&senv).unwrap()).unwrap();
        assert!(pairs.contains(&("KOTTON_PUBLIC_ADDR".into(), String::new())), "{pairs:?}");
        assert!(!pairs.iter().any(|(k, _)| k == "KOTTON_RELAY_URL"), "the installer names a relay: {pairs:?}");
        let said = over_ssh(&sshroot, "198.51.100.7", Some("198.51.100.7"));
        assert!(!said.contains("To write it, run"), "given the address, nothing is proposed: {said}");
        let pairs = env_pairs(&std::fs::read_to_string(&senv).unwrap()).unwrap();
        assert!(pairs.contains(&("KOTTON_PUBLIC_ADDR".into(), "198.51.100.7".into())), "{pairs:?}");
        assert!(!pairs.iter().any(|(k, _)| k == "KOTTON_RELAY_URL"), "the installer names a relay: {pairs:?}");
        assert_eq!(file_mode(&senv).unwrap(), 0o640);
        let set = std::fs::read_to_string(&senv).unwrap();
        let said = over_ssh(&sshroot, "192.0.2.9", None);
        assert!(!said.contains("192.0.2.9"), "a set address is not proposed over: {said}");
        let out = install(&system, Some(&sshroot), Some("192.0.2.9"));
        assert!(out.status.success(), "{}", release::said(&out));
        assert_eq!(std::fs::read_to_string(&senv).unwrap(), set, "a set address is never replaced");
        // Private and loopback addresses are proposed and named as such; an IPv6 one is
        // named and not proposed, since the installer cannot write it.
        for (arrived, says) in [("10.0.0.5", "a private address"), ("172.20.1.1", "a private address"), ("127.0.0.1", "a loopback address")] {
            let said = over_ssh(&dir.path().join(format!("ssh-{arrived}")), arrived, None);
            assert!(said.contains(&format!("arrived at {arrived} — {says}")), "{said}");
            assert!(said.contains(&format!("KOTTON_PUBLIC_ADDR={arrived} sh ")), "{said}");
        }
        let said = over_ssh(&dir.path().join("ssh-v6"), "2001:db8::7", None);
        assert!(said.contains("arrived at 2001:db8::7, an IPv6 address"), "{said}");
        assert!(!said.contains("KOTTON_PUBLIC_ADDR=2001"), "{said}");
        // At a terminal the proposal is a question, and only a yes writes: into a fresh
        // file, and into a kept file's still-empty lines. `script(1)` gives the install a
        // terminal and types the answer into it.
        #[cfg(target_os = "linux")]
        {
            let at_terminal = |root: &Path, answer: &str| {
                let mut c = system.command("script");
                c.args(["-qec", &format!("/bin/sh '{}'", tree.join("install.sh").display()), "/dev/null"])
                    .env("KOTTON_ROOT", root)
                    .env("SSH_CONNECTION", "203.0.113.40 52814 198.51.100.8 22")
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped());
                let mut child = c.spawn().unwrap();
                std::io::Write::write_all(child.stdin.as_mut().unwrap(), format!("{answer}\n").as_bytes()).unwrap();
                let out = child.wait_with_output().unwrap();
                assert!(out.status.success(), "{}", release::said(&out));
                let said = String::from_utf8_lossy(&out.stdout).to_string();
                assert!(said.contains("write KOTTON_PUBLIC_ADDR=198.51.100.8"), "asked at a terminal: {said}");
                env_pairs(&std::fs::read_to_string(root.join("etc/kotton/vault.env")).unwrap()).unwrap()
            };
            let yes = dir.path().join("tty-yes");
            let pairs = at_terminal(&yes, "y");
            assert!(pairs.contains(&("KOTTON_PUBLIC_ADDR".into(), "198.51.100.8".into())), "{pairs:?}");
            assert!(!pairs.iter().any(|(k, _)| k == "KOTTON_RELAY_URL"), "the installer names a relay: {pairs:?}");
            for answer in ["n", ""] {
                let pairs = at_terminal(&dir.path().join(format!("tty-no-{answer}")), answer);
                assert!(pairs.contains(&("KOTTON_PUBLIC_ADDR".into(), String::new())), "{answer:?}: {pairs:?}");
            }
            let kept = dir.path().join("tty-no-");
            let pairs = at_terminal(&kept, "y");
            assert!(pairs.contains(&("KOTTON_PUBLIC_ADDR".into(), "198.51.100.8".into())), "a kept blank is filled on a yes: {pairs:?}");
        }
        // Without an ssh session, nothing is proposed: as before.
        let out = install(&system, Some(&dir.path().join("nossh")), None);
        assert!(!String::from_utf8_lossy(&out.stdout).contains("ssh session"), "{}", release::said(&out));

        // Not root: into a root of its own it installs and says it made no user; onto the
        // host itself it refuses before writing anything.
        let someone = StandInSystem::new(&dir.path().join("someone"), 1000, None).unwrap();
        let staged = dir.path().join("staged");
        let out = install(&someone, Some(&staged), None);
        assert!(out.status.success(), "{}", release::said(&out));
        assert!(String::from_utf8_lossy(&out.stdout).contains("not made"));
        assert!(!someone.asked().contains("useradd"));
        // With no user made there is no group to read it: root's alone.
        assert!(!someone.asked().contains("chgrp"));
        assert_eq!(file_mode(&staged.join("etc/kotton/vault.env")).unwrap(), 0o600);
        let out = install(&someone, None, None);
        assert!(!out.status.success());
        assert!(String::from_utf8_lossy(&out.stderr).contains("run it as root"), "{}", release::said(&out));

        // Sums that do not name Kotton's own LICENSE or NOTICES are refused before
        // anything is placed: each travels with the archive, and is held to its sum.
        let sums = std::fs::read_to_string(tree.join("SHA256SUMS")).unwrap();
        for f in release::OWN {
            let without: String = sums.lines().filter(|l| !l.ends_with(&format!("  {f}"))).map(|l| format!("{l}\n")).collect();
            assert_ne!(without, sums, "SHA256SUMS names {f}");
            std::fs::write(tree.join("SHA256SUMS"), &without).unwrap();
            let bare = dir.path().join(format!("without-{f}"));
            let out = install(&system, Some(&bare), None);
            assert!(!out.status.success(), "{}", release::said(&out));
            assert!(String::from_utf8_lossy(&out.stderr).contains(&format!("SHA256SUMS does not name {f}")), "{}", release::said(&out));
            assert!(!bare.join("usr/local/bin/kvaultd").exists());
        }
        std::fs::write(tree.join("SHA256SUMS"), &sums).unwrap();

        // A binary that is not the one summed is refused, and nothing is placed.
        std::fs::write(tree.join("bin/kvaultd"), b"#!/bin/sh\necho other bytes\n").unwrap();
        let fresh = dir.path().join("fresh");
        let out = install(&system, Some(&fresh), None);
        assert!(!out.status.success(), "{}", release::said(&out));
        assert!(String::from_utf8_lossy(&out.stderr).contains("not the ones SHA256SUMS names"));
        assert!(!fresh.join("usr/local/bin/kvaultd").exists());
    }

    /// **The installer's `create` runs as the service's uid** — the property
    /// `release-server-test` holds on a real archive, held here on the script with a
    /// stand-in binary (`TASK-release-server-test-runs-the-installers-create-as-root-and-never-with-an-address`).
    /// The stood-in `runuser -u kotton-vault --` runs its command as the uid the stand-in
    /// user database gives the user, and never as this process: as root it is that uid,
    /// and as anyone else `setpriv` cannot enter it and refuses, where a `runuser` that ran
    /// the command as this process would print this process's uid. As root, the whole
    /// install with the operator's key then runs `create` as that uid, on a `0700` state
    /// directory the uid owns, reading a `0640` vault.env by group alone — read back by
    /// `created_as_its_user`, the check `release-server-test` runs, and by the uid
    /// `create` itself wrote down.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_installers_create_runs_as_the_services_uid() {
        use std::os::unix::fs::PermissionsExt as _;
        let me: u32 = String::from_utf8_lossy(&Command::new("/usr/bin/id").arg("-u").output().unwrap().stdout).trim().parse().unwrap();
        // As root, a uid nobody here has; otherwise any uid but this one.
        let service = service_uid();
        let n = service.unwrap_or(if me == 64_100 { 64_101 } else { 64_100 });
        let dir = tempfile::tempdir().unwrap();
        // The service's uid runs the installed binary from under here.
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let system = StandInSystem::new(&dir.path().join("system"), 0, Some(n)).unwrap();

        let made = system.command("useradd").args(["--system", "kotton-vault"]).status().unwrap();
        assert!(made.success());
        let out = system.command("runuser").args(["-u", "kotton-vault", "--", "/usr/bin/id", "-u"]).output().unwrap();
        let said = String::from_utf8_lossy(&out.stdout).trim().to_string();
        assert_ne!(said, me.to_string(), "the stood-in runuser ran its command as this process, uid {me}: {}", release::said(&out));
        if me == 0 {
            assert!(out.status.success(), "{}", release::said(&out));
            assert_eq!(said, n.to_string(), "{}", release::said(&out));
        } else {
            assert!(!out.status.success(), "not root, setpriv cannot enter uid {n}: {}", release::said(&out));
        }
        let Some(n) = service else {
            eprintln!("not root (or no setpriv): the stood-in runuser refused to run as this uid, and the install as uid {n} is held only as root");
            return;
        };

        let tree = dir.path().join("kotton-vault-abc-linux-x86_64");
        std::fs::create_dir_all(tree.join("bin")).unwrap();
        // `create`, as the installer calls it: it reads vault.env beside the installed
        // binary, as kvaultd does, writes down the uid it ran as into the state directory,
        // and prints its line.
        std::fs::write(
            tree.join("bin/kvaultd"),
            "#!/bin/sh\n[ \"$1\" = create ] && [ \"$2\" = --state-dir ] || exit 2\n\
             cat \"$(dirname \"$0\")/../../../etc/kotton/vault.env\" >/dev/null || exit 3\n\
             /usr/bin/id -u > \"$3/created-by\" || exit 4\n\
             echo \"kotton-instance:vault:$5@\"\n",
        )
        .unwrap();
        for (src, dst) in [
            (VAULT.unit_src, VAULT.unit()),
            (VAULT.env_src, VAULT.env()),
            (INSTALLER, "install.sh".to_string()),
        ] {
            std::fs::copy(workspace().join(src), tree.join(dst)).unwrap();
        }
        std::fs::write(tree.join("REVISION"), "abc\nbuilt for x86_64-unknown-linux-musl\n").unwrap();
        std::fs::write(tree.join(crate::license_check::FILE), "stand-in notices\n").unwrap();
        for f in release::OWN {
            std::fs::copy(workspace().join(f), tree.join(f)).unwrap();
        }
        let summed: Vec<String> = VAULT.entries().into_iter().filter(|e| e != "SHA256SUMS").collect();
        std::fs::write(tree.join("SHA256SUMS"), sum_lines(&tree, &summed).unwrap()).unwrap();

        let root = dir.path().join("root");
        let out = system
            .command("/bin/sh")
            .arg(tree.join("install.sh"))
            .env("KOTTON_ROOT", &root)
            .env("KOTTON_OPERATOR_KEY", OPERATOR_KEY)
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert!(out.status.success(), "{}", release::said(&out));
        let said = String::from_utf8_lossy(&out.stdout).to_string();
        assert_eq!(instance_line(&VAULT, &said).unwrap(), format!("kotton-instance:vault:{OPERATOR_KEY}@"), "{said}");
        created_as_its_user(&root, &VAULT, &system, Some(n)).unwrap();
        let by = std::fs::read_to_string(root.join("var/lib/kotton-vault/created-by")).unwrap();
        assert_eq!(by.trim(), n.to_string(), "`create` ran as uid {by}");
    }

    /// **The vault is static as the relay is.** One target for both, a musl one, and a
    /// binary that asks for a loader is refused by `install_into`'s step 4 — here, this
    /// test's own binary, which is dynamic on a -gnu host.
    #[test]
    fn both_servers_are_one_static_target_and_a_dynamic_binary_is_refused() {
        assert!(TARGET.ends_with("-linux-musl"), "{TARGET}");
        let mut h = vec![0u8; 64];
        h[..4].copy_from_slice(b"\x7fELF");
        h[4] = 2;
        h[5] = 1;
        assert_eq!(static_or_refused(&h, "kvaultd"), Ok(()));
        #[cfg(all(target_os = "linux", target_env = "gnu"))]
        {
            let me = std::fs::read(std::env::current_exe().unwrap()).unwrap();
            let why = static_or_refused(&me, "kvaultd").unwrap_err();
            assert!(why.contains("kvaultd asks for the loader") && why.contains("ld-linux"), "{why}");
        }
    }

    /// **What makes the vault static on musl, and only there.** `kvaultd` turns on sqlcipher's
    /// vendored OpenSSL under `cfg(target_env = "musl")` — a musl builder has no libcrypto to
    /// link — and `.cargo/config.toml` lifts `OPENSSL_NO_VENDOR` for that target by its
    /// prefixed name, leaving the bare one, which every other build reads, at `1`.
    #[test]
    fn the_vault_vendors_openssl_for_musl_alone() {
        let manifest = read("core/kvaultd/Cargo.toml");
        let musl = manifest
            .split("[target.'cfg(target_env = \"musl\")'.dependencies]")
            .nth(1)
            .expect("kvaultd has a musl-only dependency table")
            .split("\n[")
            .next()
            .unwrap();
        assert!(
            musl.lines().any(|l| l.starts_with("libsqlite3-sys") && l.contains("bundled-sqlcipher-vendored-openssl")),
            "{musl}"
        );
        let before_musl = manifest.split("[target.'cfg(target_env = \"musl\")'").next().unwrap();
        assert!(!before_musl.contains("vendored-openssl"), "vendored OpenSSL must stay musl-only");

        let config = read(".cargo/config.toml");
        let env = |key: &str| {
            config
                .lines()
                .find(|l| l.split('=').next().map(str::trim) == Some(key))
                .unwrap_or_else(|| panic!("{key} is not in .cargo/config.toml"))
                .to_string()
        };
        let prefixed = format!("{}_OPENSSL_NO_VENDOR", TARGET.to_uppercase().replace('-', "_"));
        assert!(env(&prefixed).contains("value = \"0\""), "{}", env(&prefixed));
        assert!(env("OPENSSL_NO_VENDOR").contains("value = \"1\""), "{}", env("OPENSSL_NO_VENDOR"));
    }

    /// **No C library arrives in a released server unwatched and unnamed.** Each server's
    /// closure for [`TARGET`] is read by `wx-check`'s reader along [`C_EDGES`]; every crate in
    /// it that its lockfile says depends on `cc` or `cmake` is on [`C_WATCHED`] or
    /// [`C_NOT_WATCHED`], never both — and every entry on either is still in some server's
    /// closure, so a reason cannot outlive the crate it is about
    /// (`TASK-a-released-server-carries-c-libraries-no-command-compares-with-their-newest`).
    #[test]
    fn every_crate_that_builds_c_into_a_server_is_watched_or_named() {
        let root = workspace();
        let mut seen: Vec<String> = Vec::new();
        let mut loose: Vec<String> = Vec::new();
        for server in SERVERS {
            let tree = crate::wx_check::closure(&root, &server, TARGET, C_EDGES)
                .unwrap_or_else(|e| panic!("{}: {e}", server.binary));
            let lock = std::fs::read_to_string(root.join(server.lockfile())).unwrap();
            let found = builds_c(&tree, &lock);
            assert!(!found.is_empty(), "{}: no crate in its closure builds C — the reader is not reading", server.binary);
            for (name, version) in found {
                let listed = C_WATCHED.iter().chain(C_NOT_WATCHED).filter(|(n, _)| *n == name).count();
                if listed != 1 {
                    loose.push(format!("{} {name} {version} (listed {listed} times)", server.binary));
                }
                seen.push(name);
            }
        }
        assert!(loose.is_empty(), "builds C into a released server and is not on exactly one of C_WATCHED / C_NOT_WATCHED:\n  {}", loose.join("\n  "));
        let stale: Vec<&str> =
            C_WATCHED.iter().chain(C_NOT_WATCHED).map(|(n, _)| *n).filter(|n| !seen.iter().any(|s| s == n)).collect();
        assert!(stale.is_empty(), "named, but in no server's closure: {stale:?}");
    }

    #[test]
    fn a_crate_builds_c_when_its_lock_entry_depends_on_cc_or_cmake() {
        let lock = "[[package]]\nname = \"ring\"\nversion = \"0.17.14\"\ndependencies = [\n \"cc\",\n \"libc\",\n]\n\n\
                    [[package]]\nname = \"ring\"\nversion = \"0.16.20\"\ndependencies = [\n \"cc 1.0.0\",\n]\n\n\
                    [[package]]\nname = \"aws-lc-sys\"\nversion = \"0.44.0\"\ndependencies = [\n \"cmake\",\n]\n\n\
                    [[package]]\nname = \"ccm\"\nversion = \"1.0.0\"\ndependencies = [\n \"ccm-core\",\n]\n\n\
                    [[package]]\nname = \"tokio\"\nversion = \"1.0.0\"\n";
        let tree = "kvaultd v0.1.0 (/k/core/kvaultd)\nring v0.17.14\ntokio v1.0.0\nccm v1.0.0\naws-lc-sys v0.44.0\nring v0.17.14 (*)\n";
        let found = builds_c(tree, lock);
        let s = |a: &str, b: &str| (a.to_string(), b.to_string());
        // Once each, the version the tree holds, not every version the lockfile locks.
        assert_eq!(found, [s("ring", "0.17.14"), s("aws-lc-sys", "0.44.0")]);
    }

    /// **What tells a publisher a fix exists in a server's C.** A static server's C is the one
    /// its release carries, so `release-server` compares each watched crate with the index: a
    /// newer one in the locked semver range is `cargo update` away, one past it is not, a
    /// yanked or pre-release one is no fix, and an index it could not read is said as that
    /// rather than read as "nothing newer". Held on `openssl-src` (a `300.x` range) and on
    /// `libsqlite3-sys` (a `0.28.x` one, where `0.29` is past the range, not in it).
    #[test]
    fn a_watched_crate_is_compared_with_the_newest_published() {
        let row = |v: &str, yanked: bool| format!("{{\"name\":\"x\",\"vers\":\"{v}\",\"yanked\":{yanked}}}\n");
        let index = |rows: &[(&str, bool)]| rows.iter().map(|(v, y)| row(v, *y)).collect::<String>();
        let ssl = |rows: &[(&str, bool)]| c_comparison("openssl-src", "300.6.1+3.6.3", "vault", Ok(&index(rows))).join("\n");

        let same = ssl(&[("300.5.5+3.5.5", false), ("300.6.1+3.6.3", false)]);
        assert!(same.contains("newest published:  300.6.1+3.6.3"), "{same}");
        assert!(same.contains("the locked version is the newest published"), "{same}");
        assert!(!same.contains("DIFFERS"), "{same}");

        let patch = ssl(&[("300.6.1+3.6.3", false), ("300.6.2+3.6.4", false)]);
        assert!(patch.contains("newest published:  300.6.2+3.6.4"), "{patch}");
        assert!(patch.contains("DIFFERS: 300.6.2+3.6.4 is published in 300.x — `cargo update -p openssl-src`, then release the vault"), "{patch}");
        assert!(!patch.contains("past"), "{patch}");

        let major = ssl(&[("300.6.1+3.6.3", false), ("400.0.1+4.0.2", false)]);
        assert!(major.contains("newest published:  400.0.1+4.0.2"), "{major}");
        assert!(major.contains("DIFFERS: 400.0.1+4.0.2 is past 300.x"), "{major}");
        assert!(major.contains("does not cross"), "{major}");

        let both = ssl(&[("300.6.2+3.6.4", false), ("400.0.1+4.0.2", false)]);
        assert!(both.contains("DIFFERS: 300.6.2+3.6.4 is published in 300.x"), "{both}");
        assert!(both.contains("and 400.0.1+4.0.2 is past 300.x"), "{both}");

        let not_fixes = ssl(&[("300.6.1+3.6.3", false), ("300.6.2+3.6.4", true), ("300.7.0-rc1+3.7.0", false)]);
        assert!(!not_fixes.contains("DIFFERS"), "{not_fixes}");

        let sql = |rows: &[(&str, bool)]| c_comparison("libsqlite3-sys", "0.28.0", "vault", Ok(&index(rows))).join("\n");
        let past = sql(&[("0.28.0", false), ("0.38.2", false)]);
        assert!(past.contains("DIFFERS: 0.38.2 is past 0.28.x"), "{past}");
        assert!(!past.contains("is published in"), "{past}");
        let in_range = sql(&[("0.28.0", false), ("0.28.3", false), ("0.38.2", false)]);
        assert!(in_range.contains("DIFFERS: 0.28.3 is published in 0.28.x"), "{in_range}");
        assert!(in_range.contains("and 0.38.2 is past 0.28.x"), "{in_range}");

        let unreachable =
            c_comparison("openssl-src", "300.6.1+3.6.3", "vault", Err("curl: (56) CONNECT tunnel failed, response 403")).join("\n");
        assert!(unreachable.contains("newest published:  unknown"), "{unreachable}");
        assert!(unreachable.contains("403"), "{unreachable}");
        assert!(unreachable.contains("this is not \"up to date\""), "{unreachable}");
        assert!(!unreachable.contains("is the newest published"), "{unreachable}");
    }

    /// The notice says what it read, what it compared with and when; compares a watched crate,
    /// names a named one with its reason, says an unlisted one as that, and a closure it could
    /// not read as that — and refuses nothing in any of those.
    #[test]
    fn the_notice_compares_the_watched_names_the_named_and_says_the_rest() {
        let s = |a: &str, b: &str| (a.to_string(), b.to_string());
        let found = Ok(vec![s("ring", "0.17.14"), s("blake3", "1.8.7"), s("newc-sys", "1.0.0"), s("aws-lc-sys", "0.44.0")]);
        let asked = std::cell::RefCell::new(Vec::new());
        let index = |name: &str| {
            asked.borrow_mut().push(name.to_string());
            match name {
                "ring" => Ok("{\"vers\":\"0.17.14\",\"yanked\":false}\n".to_string()),
                _ => Err("curl: (6) Could not resolve host".to_string()),
            }
        };
        let text = c_library_report(&VAULT, TARGET, "2026-09-28T12:00Z", found, index);
        assert!(text.contains("kvaultd builds C in"), "{text}");
        assert!(text.contains("-e normal,build,no-proc-macro --target x86_64-unknown-linux-musl"), "{text}");
        assert!(text.contains("compared with crates.io's index (https://index.crates.io), 2026-09-28T12:00Z"), "{text}");
        assert!(text.contains("ring 0.17.14 — ring's C"), "{text}");
        assert!(text.contains("the locked version is the newest published"), "{text}");
        assert!(text.contains("blake3 1.8.7 — not watched: its C is its own SIMD code"), "{text}");
        assert!(text.contains("newc-sys 1.0.0 — UNWATCHED AND UNNAMED"), "{text}");
        assert!(text.contains("aws-lc-sys 0.44.0 — AWS-LC\n    newest published:  unknown"), "{text}");
        // Only the watched are asked for: a named crate costs no request.
        assert_eq!(*asked.borrow(), ["ring", "aws-lc-sys"]);

        let blind = c_library_report(&RELAY, TARGET, "2026-09-28T12:00Z", Err("`cargo tree` failed".into()), |_| unreachable!());
        assert!(blind.contains("kotton-relay builds C in"), "{blind}");
        assert!(blind.contains("infra/relay/Cargo.lock"), "{blind}");
        assert!(blind.contains("could not be read (`cargo tree` failed) — nothing compared; this is not \"up to date\""), "{blind}");
    }

    #[test]
    fn a_crate_is_asked_for_at_its_place_in_the_sparse_index() {
        assert_eq!(index_url("openssl-src"), "https://index.crates.io/op/en/openssl-src");
        assert_eq!(index_url("ring"), "https://index.crates.io/ri/ng/ring");
        assert_eq!(index_url("cc"), "https://index.crates.io/2/cc");
        assert_eq!(index_url("syn"), "https://index.crates.io/3/s/syn");
        assert_eq!(index_url("a"), "https://index.crates.io/1/a");
        assert_eq!(index_url("Libsqlite3-Sys"), "https://index.crates.io/li/bs/libsqlite3-sys");
    }

    /// A released vault is tested against a released relay, never a `-not-a-release` one.
    #[test]
    fn a_released_vault_is_tested_against_a_released_relay() {
        let dir = tempfile::tempdir().unwrap();
        let scratch = dir.path().join("kotton-relay-aaaaaaaaaaaa-not-a-release-linux-x86_64.tar.gz");
        std::fs::write(&scratch, b"x").unwrap();
        assert!(relay_for_vault_test(dir.path(), "bbbbbbbbbbbb", "x86_64", true).is_err());
        assert_eq!(relay_for_vault_test(dir.path(), "bbbbbbbbbbbb", "x86_64", false).unwrap(), scratch);
        let released = dir.path().join("kotton-relay-cccccccccccc-linux-x86_64.tar.gz");
        std::fs::write(&released, b"x").unwrap();
        assert_eq!(relay_for_vault_test(dir.path(), "bbbbbbbbbbbb", "x86_64", true).unwrap(), released);
    }

    /// A unit's `ExecStart=` and `EnvironmentFile=` are read as paths.
    #[test]
    fn a_units_paths_are_read_out_of_it() {
        let unit = "[Unit]\nDescription=x\n[Service]\nEnvironmentFile=/etc/kotton/vault.env\nExecStart=/usr/local/bin/kvaultd --x\nRestart=on-failure\n[Install]\nWantedBy=multi-user.target\n";
        assert_eq!(unit_normal_form(unit, &[]), Ok(()));
        assert_eq!(
            unit_paths(unit),
            vec![("EnvironmentFile", "/etc/kotton/vault.env".to_string()), ("ExecStart", "/usr/local/bin/kvaultd".to_string())]
        );
        // Only [Service]'s are the service's; a spelling that reads two ways is refused
        // before it is read (TASK-unit-paths-reads-a-unit-by-a-spelling-systemd-does-not-require).
        assert_eq!(unit_paths(&unit.replace("Description=x", "ExecStart=/elsewhere")).len(), 2);
        for bad in ["ExecStart = /elsewhere", "ExecStart=/elsewhere \\"] {
            assert!(unit_normal_form(&unit.replace("Restart=on-failure", bad), &[]).is_err(), "{bad}");
        }
    }

    /// A static ELF has no interpreter; a dynamic one names its loader. Read from this
    /// test's own binary, which is dynamic on a -gnu host, and a hand-made header.
    #[test]
    fn the_elf_interpreter_is_read_out_of_the_program_headers() {
        assert!(elf_interpreter(b"not an elf").is_err());
        // A 64-bit little-endian header with no program headers: static.
        let mut h = vec![0u8; 64];
        h[..4].copy_from_slice(b"\x7fELF");
        h[4] = 2;
        h[5] = 1;
        assert_eq!(elf_interpreter(&h).unwrap(), None);
        #[cfg(all(target_os = "linux", target_env = "gnu"))]
        {
            let me = std::fs::read(std::env::current_exe().unwrap()).unwrap();
            assert!(elf_interpreter(&me).unwrap().unwrap().contains("ld-linux"));
        }
    }

    /// A relay and a vault whose `create` speaks as the real ones do and does nothing else:
    /// the relay prints its line with the address it was told, the vault with the one its
    /// installed settings name — what the host's installer is under test for.
    fn stand_in_binaries(dir: &Path) -> [(Server, PathBuf); 2] {
        std::fs::create_dir_all(dir).unwrap();
        let relay = dir.join("kotton-relay");
        std::fs::write(
            &relay,
            "#!/bin/sh\n[ \"$1\" = --state-dir ] && [ \"$3\" = --advertise ] && [ \"$5\" = create ] && [ \"$6\" = --operator ] || exit 2\n\
             echo \"kotton-instance:relay:$7@$4\"\n",
        )
        .unwrap();
        let vault = dir.join("kvaultd");
        std::fs::write(
            &vault,
            "#!/bin/sh\n[ \"$1\" = create ] && [ \"$2\" = --state-dir ] && [ \"$4\" = --operator ] || exit 2\n\
             addr=$(sed -n 's/^KOTTON_PUBLIC_ADDR=//p' \"$(dirname \"$0\")/../../../etc/kotton/vault.env\" | tail -n 1)\n\
             echo \"kotton-instance:vault:$5@${addr:+$addr:7710}\"\n",
        )
        .unwrap();
        [(RELAY, relay), (VAULT, vault)]
    }

    /// The host's tree, laid out by the release's own [`lay_out_host`] from the stand-ins.
    fn stand_in_host(dir: &Path) -> PathBuf {
        let bins = stand_in_binaries(&dir.join("built"));
        let tree = dir.join(archive_name(HOST, "abc", true, TARGET));
        std::fs::create_dir_all(&tree).unwrap();
        let servers: Vec<(Server, &Path, &str)> = bins.iter().map(|(s, b)| (*s, b.as_path(), "stand-in notices\n")).collect();
        lay_out_host(&workspace(), &servers, "abc\nbuilt for x86_64-unknown-linux-musl\n", &tree).unwrap();
        tree
    }

    /// Every file under `dir`, as `tar -t` lists them under its name.
    fn listing(dir: &Path) -> String {
        let top = dir.file_name().unwrap().to_string_lossy().to_string();
        let mut out = vec![format!("{top}/")];
        let mut stack = vec![dir.to_path_buf()];
        while let Some(d) = stack.pop() {
            for e in std::fs::read_dir(&d).unwrap().flatten() {
                let rel = e.path().strip_prefix(dir).unwrap().display().to_string();
                if e.path().is_dir() {
                    out.push(format!("{top}/{rel}/"));
                    stack.push(e.path());
                } else {
                    out.push(format!("{top}/{rel}"));
                }
            }
        }
        out.join("\n") + "\n"
    }

    /// **The host's archive is named `kotton-host-<rev>-linux-<arch>` and holds both servers'
    /// trees whole** — both binaries, both units, both env files, each tree's own installer and
    /// sums — beside the host's installer and sums over every file. Laid out by the release's
    /// own code, so the layout the test holds is the one packed, and the root `install.sh`'s
    /// `--kind host` downloads it by that name (`release::tests`).
    #[test]
    fn the_host_archive_is_named_for_the_host_and_holds_both_servers_trees_whole() {
        assert_eq!(archive_name(HOST, "8415af154deb", true, TARGET), "kotton-host-8415af154deb-linux-x86_64");
        assert_eq!(archive_name(HOST, "8415af154deb", false, TARGET), "kotton-host-8415af154deb-not-a-release-linux-x86_64");
        assert_eq!(Server::of_archive(Path::new("kotton-host-x.tar.gz")), None, "the host is no one server");
        let entries = host_entries();
        for want in [
            "install.sh",
            "SHA256SUMS",
            "REVISION",
            "relay/bin/kotton-relay",
            "relay/kotton-relay.service",
            "relay/relay.env",
            "relay/install.sh",
            "relay/SHA256SUMS",
            "vault/bin/kvaultd",
            "vault/kotton-vault.service",
            "vault/vault.env",
            "vault/install.sh",
            "vault/SHA256SUMS",
        ] {
            assert!(entries.iter().any(|e| e == want), "the host's archive holds no {want}: {entries:?}");
        }
        for f in release::OWN {
            assert!(entries.iter().any(|e| e == f), "{f}");
        }
        assert_eq!(entries.len(), 3 + release::OWN.len() + RELAY.entries().len() + VAULT.entries().len(), "{entries:?}");

        let dir = tempfile::tempdir().unwrap();
        let tree = stand_in_host(dir.path());
        release::check_layout(&listing(&tree), &entries).unwrap();
        assert_eq!(std::fs::read_to_string(tree.join("install.sh")).unwrap(), read(HOST_INSTALLER));
        assert_eq!(std::fs::read_to_string(tree.join("relay/install.sh")).unwrap(), read(INSTALLER));
        for sums in ["", "relay", "vault"] {
            let out = clean(Command::new("sha256sum")).args(["-c", "SHA256SUMS"]).current_dir(tree.join(sums)).output().unwrap();
            assert!(out.status.success(), "{sums}/SHA256SUMS: {}", release::said(&out));
        }
        let top = std::fs::read_to_string(tree.join("SHA256SUMS")).unwrap();
        assert!(top.lines().any(|l| l.ends_with("  relay/SHA256SUMS")) && top.lines().any(|l| l.ends_with("  vault/bin/kvaultd")), "{top}");
    }

    /// **The host's installer runs each tree's own, with a key each, asks the address once,
    /// and ends on one line naming both** — read back as `kotton enrol` reads it. From an ssh
    /// session with no terminal its line to run again names the host's installer once, or the
    /// checkout's `install.sh --kind host` when that reached it; given the address, both lines
    /// name it; at a terminal the relay's install asks and the vault's does not, and a yes is
    /// written into both. One key for two instances, a key cut short, a key for an instance it
    /// does not make, an unknown kind and a file not the one summed are each refused before
    /// anything is placed. Run with stand-in binaries and the stand-in user database, since
    /// what is under test is the script.
    #[cfg(unix)]
    #[test]
    fn the_host_installer_installs_both_with_a_key_each_asks_once_and_ends_on_one_line() {
        const OTHER: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let dir = tempfile::tempdir().unwrap();
        let tree = stand_in_host(dir.path());
        let system = StandInSystem::new(&dir.path().join("system"), 0, None).unwrap();
        let run = |root: &Path, env: &[(&str, &str)]| {
            let mut c = system.command("/bin/sh");
            c.arg(tree.join("install.sh"))
                .env("KOTTON_ROOT", root)
                .env("SSH_CONNECTION", "203.0.113.40 52814 198.51.100.7 22")
                .stdin(Stdio::null());
            for (k, v) in env {
                c.env(k, v);
            }
            c.output().unwrap()
        };
        let keys = [("KOTTON_OPERATOR_KEY_RELAY", OPERATOR_KEY), ("KOTTON_OPERATOR_KEY_VAULT", VAULT_OPERATOR_KEY)];
        let addr_of = |root: &Path, server: &Server| {
            let var = if server.name == VAULT.name { "KOTTON_PUBLIC_ADDR" } else { "KOTTON_RELAY_ADVERTISE" };
            let pairs = env_pairs(&std::fs::read_to_string(root.join("etc/kotton").join(server.env())).unwrap()).unwrap();
            pairs.into_iter().rev().find(|(k, _)| k == var).map(|(_, v)| v).unwrap_or_default()
        };

        // No terminal, no address: both installed and created, the line to run again printed
        // once, naming this installer, nothing written for the address, the start said.
        let root = dir.path().join("plain");
        let out = run(&root, &keys);
        assert!(out.status.success(), "{}", release::said(&out));
        let said = String::from_utf8_lossy(&out.stdout).to_string();
        let lines = host_line(&said).unwrap();
        assert_eq!(lines[0].1, format!("kotton-instance:relay:{OPERATOR_KEY}@"));
        assert_eq!(lines[1].1, format!("kotton-instance:vault:{VAULT_OPERATOR_KEY}@"));
        let again = format!("KOTTON_PUBLIC_ADDR=198.51.100.7 sh '{}'", tree.join("install.sh").display());
        assert_eq!(said.lines().filter(|l| l.trim() == again).count(), 1, "{said}");
        assert_eq!(said.matches("KOTTON_PUBLIC_ADDR is not set. This ssh session arrived at").count(), 1, "asked once: {said}");
        assert!(said.lines().any(|l| l.trim() == "systemctl daemon-reload && systemctl enable --now kotton-relay kotton-vault"), "{said}");
        for server in SERVERS {
            assert!(root.join("usr/local/bin").join(server.binary).exists());
            assert!(root.join("etc/systemd/system").join(server.unit()).exists());
            assert_eq!(addr_of(&root, &server), "", "{}", server.name);
            holds_its_install_but_static(&root, &server, &system);
        }

        // Reached through the checkout's install.sh: its line to run again is that script's.
        let out = run(&dir.path().join("checkout"), &[keys[0], keys[1], ("KOTTON_INSTALL_COMMAND", "sh kotton/install.sh --kind host")]);
        assert!(out.status.success(), "{}", release::said(&out));
        let said = String::from_utf8_lossy(&out.stdout).to_string();
        let again = "KOTTON_PUBLIC_ADDR=198.51.100.7 sh kotton/install.sh --kind host";
        assert_eq!(said.lines().filter(|l| l.trim() == again).count(), 1, "{said}");
        assert!(!said.contains(&tree.display().to_string()), "a path the checkout's script removes: {said}");

        // Given the address: both lines name it, and nothing is asked.
        let given = dir.path().join("given");
        let out = run(&given, &[keys[0], keys[1], ("KOTTON_PUBLIC_ADDR", "192.0.2.10")]);
        assert!(out.status.success(), "{}", release::said(&out));
        let said = String::from_utf8_lossy(&out.stdout).to_string();
        let lines = host_line(&said).unwrap();
        assert_eq!(lines[0].1, format!("kotton-instance:relay:{OPERATOR_KEY}@http://192.0.2.10:7700"));
        assert_eq!(lines[1].1, format!("kotton-instance:vault:{VAULT_OPERATOR_KEY}@192.0.2.10:7710"));
        assert!(!said.contains("To write it, run"), "{said}");

        // An upgrade: no keys, nothing created, and no line, since none was made.
        let out = run(&given, &[]);
        assert!(out.status.success(), "{}", release::said(&out));
        let said = String::from_utf8_lossy(&out.stdout).to_string();
        assert!(!said.contains("kotton-instance:"), "{said}");

        // One instance alone: its line, and the line to run again says which.
        let vault_only = dir.path().join("vault-only");
        let out = run(&vault_only, &[keys[1], ("KOTTON_HOST_KINDS", "vault")]);
        assert!(out.status.success(), "{}", release::said(&out));
        let said = String::from_utf8_lossy(&out.stdout).to_string();
        assert_eq!(said.lines().last().unwrap(), format!("kotton-instance:vault:{VAULT_OPERATOR_KEY}@"), "{said}");
        assert!(said.contains(&format!("KOTTON_PUBLIC_ADDR=198.51.100.7 KOTTON_HOST_KINDS=vault sh '{}'", tree.join("install.sh").display())), "{said}");
        assert!(!vault_only.join("usr/local/bin/kotton-relay").exists());

        // Refused before anything is placed.
        for (env, why) in [
            (vec![("KOTTON_OPERATOR_KEY", OPERATOR_KEY)], "not KOTTON_OPERATOR_KEY: one key never operates two instances"),
            (vec![keys[0], ("KOTTON_OPERATOR_KEY_VAULT", OPERATOR_KEY)], "are the same key: one key never operates two instances"),
            (vec![keys[0], ("KOTTON_OPERATOR_KEY_VAULT", &OTHER[..63])], "KOTTON_OPERATOR_KEY_VAULT is 63 characters"),
            (vec![keys[0], ("KOTTON_HOST_KINDS", "vault")], "KOTTON_OPERATOR_KEY_RELAY is given, and KOTTON_HOST_KINDS installs no relay"),
            (vec![("KOTTON_HOST_KINDS", "relay,gateway")], "KOTTON_HOST_KINDS names 'gateway'"),
            (vec![("KOTTON_HOST_KINDS", "vault,vault")], "KOTTON_HOST_KINDS names vault twice"),
        ] {
            let refused = dir.path().join("refused");
            let out = run(&refused, &env);
            let err = String::from_utf8_lossy(&out.stderr);
            assert!(!out.status.success() && err.contains(why) && err.contains("nothing was installed"), "{env:?}: {}", release::said(&out));
            assert!(!refused.join("usr").exists(), "{env:?}: placed something");
        }

        // At a terminal: the relay's install asks, a yes is written into both, and the vault's
        // install is not asked again. `script(1)` gives the install a terminal.
        #[cfg(target_os = "linux")]
        {
            let tty = dir.path().join("tty");
            let mut c = system.command("script");
            c.args(["-qec", &format!("/bin/sh '{}'", tree.join("install.sh").display()), "/dev/null"])
                .env("KOTTON_ROOT", &tty)
                .env("SSH_CONNECTION", "203.0.113.40 52814 198.51.100.8 22")
                .env(keys[0].0, keys[0].1)
                .env(keys[1].0, keys[1].1)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            let mut child = c.spawn().unwrap();
            std::io::Write::write_all(child.stdin.as_mut().unwrap(), b"y\n").unwrap();
            let out = child.wait_with_output().unwrap();
            assert!(out.status.success(), "{}", release::said(&out));
            let said = String::from_utf8_lossy(&out.stdout).to_string();
            assert_eq!(said.matches("[y/N]").count(), 1, "asked once: {said}");
            assert!(said.contains("write KOTTON_RELAY_ADVERTISE=http://198.51.100.8:7700"), "{said}");
            assert_eq!(addr_of(&tty, &RELAY), "http://198.51.100.8:7700");
            assert_eq!(addr_of(&tty, &VAULT), "198.51.100.8");
            let last = said.lines().map(str::trim).rfind(|l| !l.is_empty()).unwrap().to_string();
            assert_eq!(
                last,
                format!("kotton-instance:relay:{OPERATOR_KEY}@http://198.51.100.8:7700 kotton-instance:vault:{VAULT_OPERATOR_KEY}@198.51.100.8:7710")
            );
        }

        // A file not the one summed: refused, and nothing is placed.
        std::fs::write(tree.join("vault/bin/kvaultd"), b"#!/bin/sh\necho other bytes\n").unwrap();
        let tampered = dir.path().join("tampered");
        let out = run(&tampered, &keys);
        assert!(!out.status.success(), "{}", release::said(&out));
        assert!(String::from_utf8_lossy(&out.stderr).contains("not the ones SHA256SUMS names"), "{}", release::said(&out));
        assert!(!tampered.join("usr").exists());
    }

    /// [`holds_its_install`] but the binary's being static, which a stand-in script is not.
    fn holds_its_install_but_static(root: &Path, server: &Server, system: &StandInSystem) {
        match holds_its_install(root, server, system) {
            Ok(()) => panic!("a stand-in script passed as static"),
            Err(e) => assert!(e.contains("not a 64-bit little-endian ELF"), "{}: {e}", server.name),
        }
    }

    /// **A server's installer reached through the checkout's `install.sh` says to run that
    /// script again, which stays, and not its own path, which the checkout's script removes.**
    /// Told how it was reached by `KOTTON_INSTALL_COMMAND`; run alone, it names its own path as
    /// it always did.
    #[cfg(unix)]
    #[test]
    fn a_server_installer_reached_through_the_checkout_names_the_checkouts_script_to_run_again() {
        let dir = tempfile::tempdir().unwrap();
        let bins = stand_in_binaries(&dir.path().join("built"));
        let tree = dir.path().join(archive_name(RELAY.name, "abc", true, TARGET));
        lay_out(&workspace(), &RELAY, &bins[0].1, "abc\n", "stand-in notices\n", &tree).unwrap();
        let system = StandInSystem::new(&dir.path().join("system"), 0, None).unwrap();
        for (how, again) in [
            (Some("sh kotton/install.sh --kind relay"), "KOTTON_PUBLIC_ADDR=198.51.100.7 sh kotton/install.sh --kind relay".to_string()),
            (None, format!("KOTTON_PUBLIC_ADDR=198.51.100.7 sh '{}'", tree.join("install.sh").display())),
        ] {
            let mut c = system.command("/bin/sh");
            c.arg(tree.join("install.sh"))
                .env("KOTTON_ROOT", dir.path().join(format!("root-{}", how.is_some())))
                .env("SSH_CONNECTION", "203.0.113.40 52814 198.51.100.7 22")
                .stdin(Stdio::null());
            if let Some(h) = how {
                c.env("KOTTON_INSTALL_COMMAND", h);
            }
            let out = c.output().unwrap();
            assert!(out.status.success(), "{}", release::said(&out));
            let said = String::from_utf8_lossy(&out.stdout);
            assert_eq!(said.lines().filter(|l| l.trim() == again).count(), 1, "{how:?}: {said}");
        }
    }

    /// The archive's listing is held to its layout by the desktop release's rules.
    #[test]
    fn a_server_listing_with_anything_extra_is_refused() {
        let top = "kotton-relay-abc-linux-x86_64";
        let good: String = RELAY.entries().iter().map(|e| format!("{top}/{e}\n")).collect();
        assert!(release::check_layout(&format!("{top}/\n{top}/bin/\n{good}"), &RELAY.entries()).is_ok());
        let extra = format!("{good}{top}/bin/kvaultd\n");
        assert!(release::check_layout(&extra, &RELAY.entries()).is_err());
        let missing: String = good.lines().filter(|l| !l.ends_with("SHA256SUMS")).map(|l| format!("{l}\n")).collect();
        assert!(release::check_layout(&missing, &RELAY.entries()).is_err());
    }
}
