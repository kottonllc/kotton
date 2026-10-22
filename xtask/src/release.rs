// SPDX-License-Identifier: AGPL-3.0-or-later
//! `cargo xtask release` and `cargo xtask release-test` — the build a friend installs.
//!
//! `TASK-a-friend-cannot-install-kotton-without-a-toolchain`, `DEC-0075` row 4. Until
//! this, the only way into Kotton was a build on the machine that would run it, and a
//! friend is someone who does not have the toolchain.
//!
//! `release` builds the desktop profile `--release`, lays it out as one directory, packs
//! that into one archive, and then **runs `release-test` on the archive it just made** —
//! so no archive leaves this command that has not been installed into a clean directory
//! and made an identity from there. The test is not a separate step somebody may skip; a
//! release that fails it prints no archive name and exits non-zero.
//!
//! ## The layout, and why it is the whole design
//!
//! ```text
//! kotton-<rev>-<os>-<arch>/
//!   bin/            the daemons, the runner, the window, the CLI  (BINS)
//!   share/kotton/shell/app.wasm, manifest.toml                     the shell every path draws
//!   kotton-start    the launcher: execs bin/kuserd
//!   install.sh      copies the tree into a prefix, links two names
//!   README.txt
//!   REVISION        the commit, whether the tree was clean, the target
//!   THIRD-PARTY-NOTICES  every dependency the binaries and the three bundled apps are
//!                   built from, its version, its license and its license texts
//!   LICENSE         Kotton's own license, the repository root's            (OWN)
//!   NOTICES         Kotton's own notice, the repository root's
//! ```
//!
//! `THIRD-PARTY-NOTICES` is written by the pack from the lockfiles
//! (`license_check::notices`), never by hand, and the pack refuses to write one naming a
//! license `cargo xtask license-check` would refuse.
//!
//! The daemon finds everything it starts **beside its own executable** — the sidecars
//! always did (`sidecar_bin`), the runner does since this landed (`resolve_runner`), and
//! the shell is staged from `../share/kotton/shell` by the daemon itself at start
//! (`kuserd::installed`). So nothing in the installed tree names the machine it was built
//! on, and the process boundaries are the source tree's: one binary per process, each
//! the one `cargo build` made, none merged into another.
//!
//! ## What it deliberately does not carry
//!
//! No key, no account, no configuration, no base directory: the pack copies an explicit
//! list of files and nothing from a `.kotton*` directory can reach it. Nothing in the
//! installer or the launcher reaches a network. `release-test` holds both — it lists
//! every file in the archive against the layout above, and on Linux as root it installs,
//! starts and creates an identity inside a network namespace with no interface up.
//!
//! ## Where it builds
//!
//! In a target only this checkout writes, whatever `CARGO_TARGET_DIR` says (decision 0014):
//! the desktop's binaries under `out/release/workspace` ([`workspace_target`]) and each
//! bundled app under `out/release/guest/<app>` ([`guest_target`]). An archive is the build it
//! names; in a target other checkouts build into, cargo can take another tree's artifact for
//! this one's, and it would be packed under this commit.
//!
//! The shell the archive carries is the component the release's own build of it left under
//! `out/release/guest/kotton-shell` ([`pack_shell`]), never the checkout's
//! `guest/apps/kotton-shell/app.wasm`, which a convenience `build-apps` or `dev` also writes.
//! `kuserd` embeds the bundled apps from those checkout paths when it compiles, so the apps
//! a release's binaries embed are what the release's own app build wrote there just before
//! the workspace build. `--no-build` builds nothing: it packs the binaries as the last
//! release build left them, so the apps they embed are the ones that build embedded, and the
//! shell from that build's own component, refusing, with the path, when there is none.
//!
//! ## Which platforms
//!
//! The recipe runs where `cargo` runs, and names the archive for the platform it ran on;
//! there is no cross-build and no CI, so a platform's archive is made on a machine of that
//! platform. `tar` and `sh` are what the pack and the installer assume, which is Linux and
//! macOS; Windows is measured in the record, not claimed here.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Every binary the installed tree carries, each a process of its own.
///
/// `just desktop::build-release`'s list plus `khttpd`, which `kuserd` also starts by
/// name from beside itself (`supervise_khttpd`) when the web shell is on — a sidecar
/// the daemon can reach for and the archive lacked would be the three-retries-then-
/// `No such file or directory` failure `just/headless.just` records for `ksyncd`.
/// `the_pack_carries_every_sidecar_the_daemon_starts_by_name` holds this list against
/// the daemon's source.
pub const BINS: &[&str] = &[
    "kotton",
    "kdeviced",
    "kuserd",
    "kotton-runner",
    "kinferd",
    "ksyncd",
    "kquicd",
    "kuid",
    "khttpd",
];

/// The renderer the archive ships, per `DEC-0076`: the GPU. The same features
/// `just desktop::build-release` passes.
pub(crate) const FEATURES: &str = "kuid/kuid-desktop,kuid/kuid-gpu";

/// The guest app the archive carries as its shell.
const SHELL_APP: &str = "kotton-shell";

/// The shell's manifest, from the checkout: a source file, not a build output.
const SHELL_MANIFEST: &str = "guest/apps/kotton-shell/manifest.toml";

/// The shell's two files in `share/kotton/shell/`: the component the release's own build of
/// [`SHELL_APP`] made ([`pack_shell`]), and [`SHELL_MANIFEST`].
const SHELL: [&str; 2] = ["app.wasm", "manifest.toml"];

/// Where every archive — the desktop's and both servers' — carries its own installer: at its
/// top directory, under this name. The checkout's `install.sh` runs it from there, so the two
/// agree by this constant and not by a copy of it.
pub(crate) const ARCHIVE_INSTALLER: &str = "install.sh";

/// What an archive's file name adds to its top directory's name.
pub(crate) const PACKED: &str = ".tar.gz";

/// The launcher, the installer and the note, from `infra/release/`.
const LOOSE: [&str; 3] = ["kotton-start", ARCHIVE_INSTALLER, "README.txt"];

/// Kotton's own license and notice, copied from the repository root to the top of every
/// archive — the desktop's and both servers' — and kept in the desktop's prefix.
///
/// `THIRD-PARTY-NOTICES` says Kotton's own crates are under "Kotton's LICENSE"; this is
/// that file, carrying both texts and the boundary between them. AGPL-3.0 §4 and §5, and
/// Apache-2.0 §4(a) and §4(d), ask whoever passes the archive on to give the license and
/// the notices with it, and a friend cannot pass on a file they were not given.
/// `TASK-a-release-archive-carries-no-copy-of-kottons-own-license`.
pub(crate) const OWN: [&str; 2] = ["LICENSE", "NOTICES"];

/// The identity `release-test` creates, and looks for afterwards.
const FRIEND: &str = "friend";

pub fn release(workspace_root: &Path, args: &[String]) {
    let allow_dirty = args.iter().any(|a| a == "--allow-dirty");
    let no_build = args.iter().any(|a| a == "--no-build");

    let rev = revision(workspace_root);
    if rev.dirty && !allow_dirty {
        eprintln!(
            "release: the tree has changes git does not hold, so the archive would not be {}:",
            rev.sha
        );
        let _ = Command::new("git")
            .args(["status", "--short"])
            .current_dir(workspace_root)
            .status();
        eprintln!("  commit them, or pass --allow-dirty for an archive named `-dirty` that is not a release");
        std::process::exit(1);
    }

    let mut plan = plan(workspace_root);
    if !no_build {
        build(&mut plan);
    }

    let dist = crate::out::dist();
    let archive = pack(workspace_root, &dist, &rev, plan.apps).unwrap_or_else(|e| {
        eprintln!("release: {e}");
        std::process::exit(1);
    });

    println!("\nrelease: testing the archive it just made, installed into a clean directory");
    if let Err(e) = install_test(&archive) {
        eprintln!(
            "release: {} failed its install test, and is not a release:\n  {e}",
            archive.display()
        );
        std::process::exit(1);
    }

    let digest = sha256(&archive);
    println!("\nrelease: {}", archive.display());
    println!(
        "  sha256 {}",
        digest
            .as_deref()
            .unwrap_or("(no sha256sum or shasum on this machine)")
    );
    println!("  Send the digest by a different path than the archive; the friend checks it before unpacking.");
}

pub fn release_test(args: &[String]) {
    let Some(archive) = args.iter().find(|a| !a.starts_with("--")) else {
        eprintln!("usage: cargo xtask release-test <out/dist/kotton-….tar.gz>");
        std::process::exit(2);
    };
    match install_test(Path::new(archive)) {
        Ok(()) => println!("release-test: PASS — {archive}"),
        Err(e) => {
            eprintln!("release-test: FAIL — {archive}\n  {e}");
            std::process::exit(1);
        }
    }
}

pub(crate) struct Revision {
    pub(crate) sha: String,
    pub(crate) dirty: bool,
}

pub(crate) fn revision(workspace_root: &Path) -> Revision {
    let out = |args: &[&str]| {
        Command::new("git")
            .args(args)
            .current_dir(workspace_root)
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
    };
    let sha = out(&["rev-parse", "HEAD"]).unwrap_or_else(|| {
        eprintln!("release: cannot read the commit — is this a git checkout?");
        std::process::exit(1);
    });
    // Twelve characters, as `release-server` names its archives: the same string on
    // every machine.
    let sha = sha.chars().take(12).collect();
    let dirty = out(&["status", "--porcelain"]).is_none_or(|s| !s.is_empty());
    Revision { sha, dirty }
}

/// The desktop archive's top directory and file stem: `kotton-<rev>[-dirty]-<os>-<arch>`, the
/// name the checkout's `install.sh` composes from the tag's commit and the machine.
pub(crate) fn archive_name(rev: &Revision) -> String {
    format!(
        "kotton-{}{}-{}",
        rev.sha,
        if rev.dirty { "-dirty" } else { "" },
        platform()
    )
}

/// The archive's platform name, from the platform `xtask` itself was built for —
/// which is the host `cargo build` builds for, since there is no `--target` here.
fn platform() -> String {
    format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH)
}

/// Every private target the release builds in sits under this one, `out/release`.
pub(crate) fn target() -> PathBuf {
    crate::out::private_target("release")
}

/// Under `out/`, where the release builds the workspace: the desktop's binaries, and the
/// vault `release-server` packs.
const WORKSPACE: &str = "release/workspace";

/// Under `out/`, where `release-server` builds the relay, a workspace of its own.
pub(crate) const RELAY: &str = "release/relay";

/// Under `out/`, where the release builds the guest app `app` it bundles.
fn guest(app: &str) -> String {
    format!("release/guest/{app}")
}

/// Where the release builds the workspace — the desktop's binaries, and the vault
/// `release-server` packs: `out/release/workspace`, never `CARGO_TARGET_DIR`.
pub(crate) fn workspace_target() -> PathBuf {
    crate::out::private_target(WORKSPACE)
}

/// Where the release builds the guest app `app` it bundles: `out/release/guest/<app>`, never
/// `CARGO_TARGET_DIR`. `kuserd` embeds the apps it is compiled beside, and the archive
/// carries the shell, so these ship as surely as the binaries do.
pub(crate) fn guest_target(app: &str) -> PathBuf {
    crate::out::private_target(&guest(app))
}

/// The build caches the release builds leave under the checkout at `root`, one per target it
/// hands cargo — the workspace's, the relay's and each guest app's: what `reclaim` prunes
/// alongside the merge gate's.
pub(crate) fn caches(root: &Path) -> Vec<PathBuf> {
    let mut caches = vec![
        crate::out::private_target_in(root, WORKSPACE),
        crate::out::private_target_in(root, RELAY),
    ];
    caches.extend(crate::guest_app_names().map(|app| crate::out::private_target_in(root, &guest(app))));
    caches
}

/// Where the desktop's binaries are once [`build_command`] has run.
fn built_dir() -> PathBuf {
    workspace_target().join("release")
}

/// The desktop's build: every binary in [`BINS`], `--release`, with the archive's features,
/// into [`workspace_target`].
fn build_command(workspace_root: &Path) -> Command {
    let mut cargo = Command::new("cargo");
    cargo.args(["build", "--release"]);
    for b in BINS {
        cargo.args(["--bin", b]);
    }
    cargo.args(["--features", FEATURES]).arg("--target-dir").arg(workspace_target());
    cargo.current_dir(workspace_root);
    cargo
}

/// What the release builds, and where: the target each bundled app builds in, which `build`
/// hands `build_apps` and `pack` reads the shell from, and the desktop's build command.
/// `build` runs exactly this and nothing else, so what a test reads of it is what runs.
struct Build {
    apps: fn(&str) -> PathBuf,
    desktop: Command,
}

fn plan(workspace_root: &Path) -> Build {
    Build {
        apps: guest_target,
        desktop: build_command(workspace_root),
    }
}

fn build(plan: &mut Build) {
    // The apps first, in this process, so they build in the release's own targets and not in
    // a developer's. `build_apps` also writes each component to `<app dir>/app.wasm`, and
    // `kuserd` embeds those when it compiles (`bundled_apps_present`), so the binary the
    // desktop build makes next embeds what this build just wrote there.
    crate::build_apps(false, plan.apps);
    let status = plan.desktop.status().unwrap_or_else(|e| {
        eprintln!("release: could not start cargo build --release: {e}");
        std::process::exit(1);
    });
    if !status.success() {
        eprintln!("release: cargo build --release failed");
        std::process::exit(1);
    }
}

fn exe(name: &str) -> String {
    format!("{name}{}", std::env::consts::EXE_SUFFIX)
}

/// Copy the shell into `into`: its component from where the release's own build of it went
/// (`apps(SHELL_APP)`), never the checkout's `guest/apps/kotton-shell/app.wasm`, which a
/// convenience `build-apps` or `dev` also writes; and its manifest from the checkout. With
/// `--no-build` the component is the one the last release build left there, and none there
/// is a refusal naming where it was looked for.
fn pack_shell(workspace_root: &Path, app_target: &Path, into: &Path) -> Result<(), String> {
    let wasm = crate::guest_wasm(app_target, SHELL_APP)
        .ok_or_else(|| format!("build-apps does not build {SHELL_APP}, the shell the archive carries"))?;
    if !wasm.is_file() {
        return Err(format!(
            "{} is not there: the archive carries the shell the release's own build made, never the checkout's copy\n  build it: cargo xtask release (without --no-build)",
            wasm.display()
        ));
    }
    copy(&wasm, &into.join(SHELL[0]))?;
    copy(&workspace_root.join(SHELL_MANIFEST), &into.join(SHELL[1]))
}

/// Lay the tree out under `out/dist/<name>/` and pack it as `out/dist/<name>.tar.gz`.
fn pack(
    workspace_root: &Path,
    dist: &Path,
    rev: &Revision,
    apps: fn(&str) -> PathBuf,
) -> Result<PathBuf, String> {
    let name = archive_name(rev);
    let root = dist.join(&name);
    if root.exists() {
        std::fs::remove_dir_all(&root)
            .map_err(|e| format!("cannot clear {}: {e}", root.display()))?;
    }
    let bin = root.join("bin");
    let shell = root.join("share").join("kotton").join("shell");
    for d in [&bin, &shell] {
        std::fs::create_dir_all(d).map_err(|e| format!("cannot create {}: {e}", d.display()))?;
    }

    // Where `build` put them: the release's own target, never `CARGO_TARGET_DIR`.
    let release = built_dir();
    for b in BINS {
        let src = release.join(exe(b));
        copy(&src, &bin.join(exe(b)))
            .map_err(|e| format!("{e}\n  build it: cargo xtask release (without --no-build)"))?;
    }
    pack_shell(workspace_root, &apps(SHELL_APP), &shell)?;
    for f in LOOSE {
        copy(&workspace_root.join("infra/release").join(f), &root.join(f))?;
    }
    for f in OWN {
        copy(&workspace_root.join(f), &root.join(f))?;
    }
    std::fs::write(
        root.join("REVISION"),
        format!(
            "{}{}\nbuilt for {}\nrenderer gpu\n",
            rev.sha,
            if rev.dirty {
                " (a tree with uncommitted changes: not a release)"
            } else {
                ""
            },
            platform()
        ),
    )
    .map_err(|e| format!("cannot write REVISION: {e}"))?;
    let notices = crate::license_check::notices(workspace_root, &crate::license_check::DESKTOP, &name, None)?;
    std::fs::write(root.join(crate::license_check::FILE), notices)
        .map_err(|e| format!("cannot write {}: {e}", crate::license_check::FILE))?;

    let archive = dist.join(format!("{name}{PACKED}"));
    let _ = std::fs::remove_file(&archive);
    let status = Command::new("tar")
        .arg("-czf")
        .arg(&archive)
        .arg("-C")
        .arg(dist)
        .arg(&name)
        .status()
        .map_err(|e| format!("cannot run tar: {e}"))?;
    if !status.success() {
        return Err(format!("tar could not pack {}", root.display()));
    }
    println!("release: packed {}", archive.display());
    Ok(archive)
}

/// Copy one file, keeping its mode, and say which one when it is missing.
pub(crate) fn copy(src: &Path, dst: &Path) -> Result<(), String> {
    std::fs::copy(src, dst)
        .map(|_| ())
        .map_err(|e| format!("cannot copy {}: {e}", src.display()))
}

/// Every path the archive may hold, relative to its top directory, sorted.
fn expected_entries() -> Vec<String> {
    let mut v: Vec<String> = BINS.iter().map(|b| format!("bin/{}", exe(b))).collect();
    v.extend(SHELL.iter().map(|d| format!("share/kotton/shell/{d}")));
    v.extend(LOOSE.iter().map(|f| f.to_string()));
    v.extend(OWN.iter().map(|f| f.to_string()));
    v.push("REVISION".to_string());
    v.push(crate::license_check::FILE.to_string());
    v.sort();
    v
}

/// Install `archive` into a clean directory and make an identity from it.
///
/// What it does, in order, each step a process of its own:
///
/// 1. lists the archive and refuses any file the layout does not name — a key, a
///    base directory, a stray build product;
/// 2. unpacks it, holds its `THIRD-PARTY-NOTICES` to that file's shape
///    (`license_check::check_notices`), and runs `install.sh` into a prefix under a fresh
///    directory, with a `HOME` there too, so the platform-default base directory is a new
///    one — and the installed prefix keeps the notices, and Kotton's own [`OWN`];
/// 3. runs `kotton-start` from the installed prefix — the launcher a person runs —
///    and waits for the daemon's socket;
/// 4. runs `kotton id create friend` from the installed prefix **at a terminal**, the
///    way a person does, pressing Enter to take the suggested passphrase;
/// 5. runs `kotton id list` and finds the identity, and checks the daemon staged the
///    shell it shipped with into the new base directory.
///
/// Every process gets an empty environment except `HOME` and a `PATH` of the system
/// directories only, so no `cargo`, `rustc` or checkout on this machine can be what
/// made a step work. On Linux as root, steps 2–5 run in a network namespace with no
/// interface up, so none of them can have reached anything.
pub fn install_test(archive: &Path) -> Result<(), String> {
    let archive = archive
        .canonicalize()
        .map_err(|e| format!("cannot read {}: {e}", archive.display()))?;

    // 1. What is in it.
    let listing = Command::new("tar")
        .arg("-tzf")
        .arg(&archive)
        .output()
        .map_err(|e| format!("cannot run tar: {e}"))?;
    if !listing.status.success() {
        return Err(format!("tar cannot list {}", archive.display()));
    }
    let listed = String::from_utf8_lossy(&listing.stdout).to_string();
    check_entries(&listed)?;
    // Names are not enough: every entry must be a plain file or a directory. A link
    // named `bin/kotton-runner` would pass the name check and run something else.
    let verbose = Command::new("tar")
        .arg("-tvzf")
        .arg(&archive)
        .output()
        .map_err(|e| format!("cannot run tar: {e}"))?;
    check_entry_types(&String::from_utf8_lossy(&verbose.stdout))?;
    let top = listed
        .lines()
        .next()
        .and_then(|l| l.split('/').next())
        .ok_or("the archive is empty")?
        .to_string();

    // A fresh directory. The daemon's door is found by the daemon's own rule
    // wherever this puts it (step 3), so its length is not what the test rests on.
    let scratch = std::env::temp_dir().join(format!("kfi-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&scratch);
    let home = scratch.join("h");
    std::fs::create_dir_all(&home).map_err(|e| format!("cannot create {}: {e}", home.display()))?;
    let result = install_test_in(&archive, &scratch, &home, &top);
    if result.is_ok() {
        let _ = std::fs::remove_dir_all(&scratch);
    } else {
        eprintln!("release-test: left {} for inspection", scratch.display());
    }
    result
}

/// Hold an archive's listing to the layout: one top directory, and under it exactly
/// [`expected_entries`] plus the directories that hold them.
///
/// Every line is judged, not only the ones under the top directory: a file at the
/// archive's root, under a second top directory, or reached through `..` is outside
/// the layout, and is exactly where a key planted beside a real build would sit.
fn check_entries(listed: &str) -> Result<(), String> {
    check_layout(listed, &expected_entries())
}

/// [`check_entries`] against any layout: `release-server`'s archives are held to
/// theirs by the same rules.
pub(crate) fn check_layout(listed: &str, expected: &[String]) -> Result<(), String> {
    let lines: Vec<&str> = listed.lines().filter(|l| !l.is_empty()).collect();
    let top = lines
        .first()
        .and_then(|l| l.split('/').next())
        .filter(|t| !t.is_empty() && *t != "." && *t != "..")
        .ok_or("the archive is empty, or its first entry has no directory")?;
    // The directories the layout has: every proper prefix of an expected file.
    let dirs: Vec<String> = expected
        .iter()
        .flat_map(|f| {
            let parts: Vec<&str> = f.split('/').collect();
            (1..parts.len()).map(move |n| parts[..n].join("/"))
        })
        .collect();

    let mut files = Vec::new();
    let mut outside = Vec::new();
    for line in lines {
        let inner = line.strip_prefix(top).and_then(|rest| {
            if rest.is_empty() {
                Some("")
            } else {
                rest.strip_prefix('/')
            }
        });
        match inner {
            Some(rest) if rest.split('/').any(|c| c == "..") => outside.push(line.to_string()),
            Some("") => {}
            Some(rest) if rest.ends_with('/') => {
                if !dirs.iter().any(|d| d == rest.trim_end_matches('/')) {
                    outside.push(line.to_string());
                }
            }
            // Twice is refused: `tar` keeps the last copy on unpack, so a second
            // entry under a real name replaces what the first one was.
            Some(rest) if files.iter().any(|f| f == rest) => outside.push(line.to_string()),
            Some(rest) => files.push(rest.to_string()),
            None => outside.push(line.to_string()),
        }
    }
    files.sort();
    let extra: Vec<String> = files
        .iter()
        .filter(|f| !expected.contains(f))
        .cloned()
        .chain(outside)
        .collect();
    let missing: Vec<_> = expected.iter().filter(|f| !files.contains(f)).collect();
    if !extra.is_empty() || !missing.is_empty() {
        return Err(format!(
            "the archive is not the layout: extra {extra:?}, missing {missing:?}"
        ));
    }
    Ok(())
}

/// Refuse any entry of `tar -tv`'s listing that is not a plain file (`-`) or a
/// directory (`d`): a symlink, a hard link, a device or a fifo is outside the layout
/// whatever its name.
pub(crate) fn check_entry_types(verbose: &str) -> Result<(), String> {
    let odd: Vec<&str> = verbose
        .lines()
        .filter(|l| !l.is_empty() && !l.starts_with('-') && !l.starts_with('d'))
        .collect();
    if odd.is_empty() {
        Ok(())
    } else {
        Err(format!("the archive holds entries that are not plain files or directories: {odd:?}"))
    }
}

/// The system directories, and nothing a developer added: no `~/.cargo/bin`.
pub(crate) const SYSTEM_PATH: &str = "/usr/local/sbin:/usr/sbin:/sbin:/usr/bin:/bin";

/// Whether this process can put a child in a network namespace of its own:
/// `unshare -n` works for root on Linux and nowhere else this runs.
fn offline_wrapper() -> Option<&'static str> {
    if !cfg!(target_os = "linux") {
        return None;
    }
    let ok = Command::new("unshare")
        .args(["-n", "true"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    ok.then_some("unshare")
}

fn install_test_in(archive: &Path, scratch: &Path, home: &Path, top: &str) -> Result<(), String> {
    let offline = offline_wrapper();
    match offline {
        Some(_) => println!("release-test: offline — every step runs in a network namespace with no interface up"),
        None => println!("release-test: not offline — this machine cannot make a network namespace (needs root on Linux), so absence of network use is not proven here"),
    }
    // Everything below runs with this environment and nothing else.
    let home_s = home
        .to_str()
        .ok_or("the scratch path is not UTF-8")?
        .to_string();
    let envs: Vec<(&str, &str)> = vec![("HOME", &home_s), ("PATH", SYSTEM_PATH)];
    let command = |program: &Path| {
        let mut c = match offline {
            Some(u) => {
                let mut c = Command::new(u);
                c.arg("-n").arg(program);
                c
            }
            None => Command::new(program),
        };
        c.env_clear();
        for (k, v) in &envs {
            c.env(k, v);
        }
        c
    };

    // 2. Unpack and install.
    let unpacked = scratch.join("unpacked");
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
    let notices = std::fs::read_to_string(unpacked.join(top).join(crate::license_check::FILE))
        .map_err(|e| format!("the archive carries no readable {}: {e}", crate::license_check::FILE))?;
    let listed = crate::license_check::check_notices(&notices)?;
    println!("release-test: {} lists {listed} third-party packages", crate::license_check::FILE);
    // `kuid` embeds the faces the shell is set in, so the archive that ships it names them.
    crate::license_check::check_fonts_named(&notices, "kuid")?;
    println!("release-test: {} names the fonts kuid embeds", crate::license_check::FILE);
    let own: Vec<(&str, Vec<u8>)> = OWN
        .iter()
        .map(|f| {
            std::fs::read(unpacked.join(top).join(f))
                .map(|b| (*f, b))
                .map_err(|e| format!("the archive carries no readable {f}: {e}"))
        })
        .collect::<Result<_, _>>()?;
    let prefix = scratch.join("opt").join("kotton");
    let out = command(Path::new("/bin/sh"))
        .arg(unpacked.join(top).join(ARCHIVE_INSTALLER))
        .env("KOTTON_PREFIX", &prefix)
        .env("KOTTON_BINDIR", scratch.join("bin"))
        .output()
        .map_err(|e| format!("cannot run install.sh: {e}"))?;
    if !out.status.success() {
        return Err(format!("install.sh failed:\n{}", said(&out)));
    }
    // The unpacked copy goes, so nothing below can be running out of it.
    std::fs::remove_dir_all(&unpacked).map_err(|e| e.to_string())?;
    if std::fs::read_to_string(prefix.join(crate::license_check::FILE)).ok().as_deref() != Some(notices.as_str()) {
        return Err(format!("install.sh did not place the archive's {} in the prefix", crate::license_check::FILE));
    }
    for (f, bytes) in &own {
        if std::fs::read(prefix.join(f)).ok().as_ref() != Some(bytes) {
            return Err(format!("install.sh did not place the archive's {f} in the prefix"));
        }
    }
    println!("release-test: the installed prefix keeps {}", OWN.join(" and "));
    let kotton = prefix.join("bin").join(exe("kotton"));

    // 3. Start it, as a person does. Its base directory and its door are where the
    //    daemon's own rules put them in the environment `command` gives it, asked of
    //    those rules rather than joined here. A hand join is tier 3 without the move
    //    to `/tmp/kotton-<hash>/`, so under a long `TMPDIR`, which the scratch `HOME`
    //    sits in, it would wait 60 s at a door nobody opened
    //    (`TASK-two-harnesses-still-derive-a-daemons-door-by-a-copy-of-the-rule`).
    let env = |key: &str| envs.iter().find(|(k, _)| *k == key).map(|(_, v)| (*v).to_string());
    let base = kotton_common::paths::base_dir_in(&env).map_err(|e| e.to_string())?;
    // The door is `kotton_common::paths::kuserd_door_in` over the environment
    // `command` gives the `kuserd` that `kotton-start` execs; `kotton-start` adds only
    // `RUST_LOG`, which it does not read. Off unix the door is a named pipe, not a path
    // this test can wait on.
    #[cfg(unix)]
    let socket = kotton_common::paths::kuserd_door_in(&env).map_err(|e| e.to_string())?;
    #[cfg(not(unix))]
    let socket: PathBuf = Err("the release test waits for the daemon's door as a unix socket path, and this platform has none".to_string())?;
    let log = std::fs::File::create(scratch.join("daemon.log")).map_err(|e| e.to_string())?;
    let log2 = log.try_clone().map_err(|e| e.to_string())?;
    let mut daemon = command(&prefix.join("kotton-start"))
        .env("RUST_LOG", "info")
        .stdout(log)
        .stderr(log2)
        .spawn()
        .map_err(|e| format!("cannot run kotton-start: {e}"))?;

    let outcome = (|| {
        let deadline = Instant::now() + Duration::from_secs(60);
        while !socket.exists() {
            if let Ok(Some(status)) = daemon.try_wait() {
                return Err(format!(
                    "the daemon exited ({status}) before it listened:\n{}",
                    daemon_log(scratch)
                ));
            }
            if Instant::now() > deadline {
                return Err(format!(
                    "no daemon socket at {} after 60 s:\n{}",
                    socket.display(),
                    daemon_log(scratch)
                ));
            }
            std::thread::sleep(Duration::from_millis(200));
        }

        // 4. `kotton id create`, at a terminal, from the installed prefix. The one answer
        //    is Enter: take the suggested passphrase, which is what the prompt offers.
        //    The pty driver carries this process's PATH to the child, so it is set
        //    to the system directories for the length of the call.
        let (program, args): (PathBuf, Vec<String>) = match offline {
            Some(u) => (
                PathBuf::from(u),
                vec![
                    "-n".into(),
                    kotton.display().to_string(),
                    "id".into(),
                    "create".into(),
                    FRIEND.into(),
                ],
            ),
            None => (
                kotton.clone(),
                vec!["id".into(), "create".into(), FRIEND.into()],
            ),
        };
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        let saved_path = std::env::var_os("PATH");
        std::env::set_var("PATH", SYSTEM_PATH);
        let t = kotton_pty_drive::run_on_a_terminal(
            &program,
            &args,
            &[("HOME", &home_s)],
            &[""],
            Duration::from_secs(60),
        );
        match saved_path {
            Some(p) => std::env::set_var("PATH", p),
            None => std::env::remove_var("PATH"),
        }
        if !t.ok || t.unasked != 0 {
            return Err(format!(
                "`kotton id create {FRIEND}` from the installed prefix failed (unasked answers: {}):\n{}",
                t.unasked, t.text
            ));
        }
        println!("release-test: `kotton id create {FRIEND}` from the installed prefix succeeded");

        // 5. The identity is there, and the daemon staged the shell it shipped with.
        let out = command(&kotton)
            .args(["id", "list"])
            .stdin(Stdio::null())
            .output()
            .map_err(|e| format!("cannot run kotton id list: {e}"))?;
        if !out.status.success() || !String::from_utf8_lossy(&out.stdout).contains(FRIEND) {
            return Err(format!(
                "`kotton id list` does not show {FRIEND}:\n{}",
                said(&out)
            ));
        }
        let shipped =
            std::fs::read(prefix.join("share/kotton/shell/app.wasm")).map_err(|e| e.to_string())?;
        let staged = std::fs::read(base.join("system/shell/app.wasm")).map_err(|e| {
            format!(
                "the daemon staged no shell into {}: {e}\n{}",
                base.display(),
                daemon_log(scratch)
            )
        })?;
        if shipped != staged {
            return Err("the staged shell is not the one the archive shipped".into());
        }
        println!(
            "release-test: the daemon staged the shell it shipped with into the new base directory"
        );
        Ok(())
    })();

    stop(&mut daemon);
    let left = stop_what_it_left(&prefix);
    if !left.is_empty() {
        println!("release-test: the daemon left these running after it stopped, and they were killed: {left:?}");
    }
    outcome
}

/// Stop the launcher's daemon and anything it started (`kuid`, the sidecars), which
/// run from the installed prefix and would otherwise outlive the test.
fn stop(daemon: &mut std::process::Child) {
    #[cfg(unix)]
    {
        let _ = Command::new("kill")
            .arg("-TERM")
            .arg(daemon.id().to_string())
            .status();
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if let Ok(Some(_)) = daemon.try_wait() {
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }
    let _ = daemon.kill();
    let _ = daemon.wait();
}

/// Anything still running out of the installed prefix — a sidecar or a window the
/// daemon started and did not take down with it. Named in the test's output rather
/// than left behind, so a daemon that orphans its children is seen.
fn stop_what_it_left(prefix: &Path) -> Vec<String> {
    let mut left = Vec::new();
    #[cfg(target_os = "linux")]
    if let Ok(entries) = std::fs::read_dir("/proc") {
        for e in entries.flatten() {
            let Ok(exe) = std::fs::read_link(e.path().join("exe")) else {
                continue;
            };
            if exe.starts_with(prefix) {
                left.push(format!(
                    "{} (pid {})",
                    exe.display(),
                    e.file_name().to_string_lossy()
                ));
                let _ = Command::new("kill")
                    .arg("-KILL")
                    .arg(e.file_name())
                    .status();
            }
        }
    }
    left
}

fn daemon_log(scratch: &Path) -> String {
    let text = std::fs::read_to_string(scratch.join("daemon.log")).unwrap_or_default();
    let lines: Vec<&str> = text.lines().collect();
    lines[lines.len().saturating_sub(30)..].join("\n")
}

pub(crate) fn said(out: &std::process::Output) -> String {
    format!(
        "status: {}\n--- stdout ---\n{}\n--- stderr ---\n{}",
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

pub(crate) fn sha256(path: &Path) -> Option<String> {
    for (prog, args) in [("sha256sum", vec![]), ("shasum", vec!["-a", "256"])] {
        if let Ok(o) = Command::new(prog).args(&args).arg(path).output() {
            if o.status.success() {
                return String::from_utf8_lossy(&o.stdout)
                    .split_whitespace()
                    .next()
                    .map(str::to_string);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn workspace() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .to_path_buf()
    }

    /// **The install test waits for the daemon's door where the daemon binds it**, with
    /// the environment `install_test_in` gives it, at any depth. Under a `HOME` deep
    /// enough that tier 3 joined by hand, `.local/share/kotton/run/kuserd.sock`, is over
    /// 103 bytes, the kernel refuses to bind the joined path; the path `kuserd_door_in`
    /// names binds, and it is not the joined one. Under a short `HOME` the two are the
    /// same path, which is what a friend's machine gets
    /// (`TASK-two-harnesses-still-derive-a-daemons-door-by-a-copy-of-the-rule`). Linux
    /// only: the joined path is Linux's default base directory.
    #[cfg(target_os = "linux")]
    #[test]
    fn the_daemons_door_is_found_where_it_binds_at_any_depth() {
        use std::os::unix::net::UnixListener;
        let scratch = tempfile::tempdir().unwrap();
        let door_under = |home: &Path| {
            let home = home.to_str().unwrap().to_string();
            let env = |key: &str| match key {
                "HOME" => Some(home.clone()),
                "PATH" => Some(SYSTEM_PATH.to_string()),
                _ => None,
            };
            let found = kotton_common::paths::kuserd_door_in(&env).unwrap();
            let joined = Path::new(&home).join(".local/share/kotton/run/kuserd.sock");
            (found, joined)
        };

        // Deep: over 103 bytes joined, which no bind accepts.
        let (found, joined) = door_under(&scratch.path().join("a".repeat(60)).join("h"));
        assert!(joined.as_os_str().len() > 103, "{} is not deep enough", joined.display());
        std::fs::create_dir_all(joined.parent().unwrap()).unwrap();
        assert!(UnixListener::bind(&joined).is_err(), "{} bound; the scratch is not deep enough", joined.display());
        assert_ne!(found, joined, "the door was joined by hand");
        std::fs::create_dir_all(found.parent().unwrap()).unwrap();
        let bound = UnixListener::bind(&found);
        let _ = std::fs::remove_dir_all(found.parent().unwrap());
        bound.unwrap_or_else(|e| panic!("{} does not bind: {e}", found.display()));

        // Shallow: the joined path.
        let (found, joined) = door_under(&scratch.path().join("h"));
        assert!(joined.as_os_str().len() <= 103, "{}", joined.display());
        assert_eq!(found, joined);
    }

    /// Every name the daemon starts through `sidecar_bin("…")` is in the archive.
    ///
    /// The list in [`BINS`] is a second statement of which processes the daemon
    /// reaches for, and a second statement is only safe while something compares
    /// them: a sidecar added to the daemon and not to the archive is a friend's
    /// install that retries it three times and gives up.
    #[test]
    fn the_pack_carries_every_sidecar_the_daemon_starts_by_name() {
        let src =
            std::fs::read_to_string(workspace().join("core/kuserd/src/agent/mod.rs")).unwrap();
        let mut named = Vec::new();
        for part in src.split("sidecar_bin(\"").skip(1) {
            if let Some(name) = part.split('"').next() {
                named.push(name.to_string());
            }
        }
        assert!(
            !named.is_empty(),
            "no sidecar_bin(\"…\") calls found — did the daemon move?"
        );
        for n in &named {
            assert!(
                BINS.contains(&n.as_str()),
                "the daemon starts `{n}` by name and the archive does not carry it"
            );
        }
        // And the runner, which it finds beside itself by `resolve_runner`.
        assert!(BINS.contains(&"kotton-runner"));
    }

    /// **The desktop's archive is built, and packed from, targets only this checkout
    /// writes**, with `CARGO_TARGET_DIR` exported elsewhere. Read from the plan `build` runs
    /// and nothing else: the apps target it hands `build_apps` is `out/release/guest/<app>`
    /// for every app, the desktop's command hands cargo `out/release/workspace`, and the pack
    /// reads the binaries from there.
    #[test]
    fn the_desktop_release_builds_in_a_target_of_its_own_under_an_exported_cargo_target_dir() {
        crate::out::exported::run(
            concat!(
                module_path!(),
                "::the_desktop_release_builds_in_a_target_of_its_own_under_an_exported_cargo_target_dir"
            ),
            |exported| {
                let root = crate::out::root();
                let plan = plan(&root);
                let apps_under = root.join("out").join("release").join("guest");
                for app in crate::guest_app_names() {
                    let target = (plan.apps)(app);
                    assert_eq!(target, apps_under.join(app), "build_apps is handed the release's target for {app}");
                    crate::out::exported::assert_private(app, &target, exported);
                }
                let dir = target_dir_of(&plan.desktop);
                assert_eq!(dir, workspace_target());
                crate::out::exported::assert_private("the desktop build", &dir, exported);
                assert!(built_dir().starts_with(&dir), "the pack reads where the build wrote");
                crate::out::exported::assert_private("the desktop pack", &built_dir(), exported);
            },
        );
    }

    /// **The archive's shell is the component the release's own build made**: the pack copies
    /// it from under the apps target `build` hands `build_apps`, and never from the
    /// checkout's `guest/apps/kotton-shell/app.wasm`, which a convenience build also writes.
    #[test]
    fn the_shell_is_packed_from_the_release_builds_own_component() {
        let root = crate::out::root();
        let shell_target = (plan(&root).apps)(SHELL_APP);
        let wasm = crate::guest_wasm(&shell_target, SHELL_APP).expect("build_apps builds the shell");
        assert!(wasm.starts_with(guest_target(SHELL_APP)), "{}", wasm.display());
        assert_ne!(wasm, root.join("guest/apps/kotton-shell/app.wasm"));

        // And the copy is that file's bytes: a stand-in target holding a component the
        // checkout's copy cannot be.
        let tmp = tempfile::tempdir().unwrap();
        let target = tmp.path().join("target");
        let made = crate::guest_wasm(&target, SHELL_APP).unwrap();
        std::fs::create_dir_all(made.parent().unwrap()).unwrap();
        std::fs::write(&made, b"the release build's own shell").unwrap();
        let into = tmp.path().join("shell");
        std::fs::create_dir_all(&into).unwrap();
        pack_shell(&root, &target, &into).unwrap();
        assert_eq!(std::fs::read(into.join("app.wasm")).unwrap(), b"the release build's own shell");
        assert!(into.join("manifest.toml").is_file());
    }

    /// **`--no-build` with no shell from a release build is a refusal naming where it looked**,
    /// whatever the checkout's own `app.wasm` holds; nothing is packed in its place.
    #[test]
    fn no_build_without_the_release_builds_shell_is_refused_naming_it() {
        let root = crate::out::root();
        let tmp = tempfile::tempdir().unwrap();
        let target = tmp.path().join("target");
        let into = tmp.path().join("shell");
        std::fs::create_dir_all(&into).unwrap();
        let refused = pack_shell(&root, &target, &into).expect_err("no component, no pack");
        let wanted = crate::guest_wasm(&target, SHELL_APP).unwrap();
        assert!(refused.contains(&wanted.display().to_string()), "{refused}");
        assert!(refused.contains("cargo xtask release"), "{refused}");
        assert!(!into.join("app.wasm").exists(), "nothing was packed in its place");
    }

    /// What `reclaim` prunes for the release is exactly where the release's builds go, read
    /// from the commands and the plan they run: the desktop's `--target-dir`, the relay's
    /// (the vault shares the desktop's), and the apps target `build` hands `build_apps` for
    /// every app — as `merge::caches` is held to the gate's targets.
    #[test]
    fn the_release_caches_are_the_targets_the_release_builds_in() {
        use crate::release_server::{build_command as server_build, RELAY, SERVERS, TARGET};
        let root = crate::out::root();
        let plan = plan(&root);
        let mut passed = vec![target_dir_of(&plan.desktop), target_dir_of(&server_build(&root, &RELAY, TARGET))];
        let apps: Vec<_> = crate::guest_app_names().collect();
        assert!(apps.contains(&SHELL_APP), "the shell the archive carries is built: {apps:?}");
        passed.extend(apps.iter().map(|app| (plan.apps)(app)));
        assert_eq!(caches(&root), passed);
        for server in SERVERS {
            let dir = target_dir_of(&server_build(&root, &server, TARGET));
            assert!(passed.contains(&dir), "{} builds in {}, a cache reclaim knows", server.name, dir.display());
        }
    }

    /// The `--target-dir` a cargo command was handed.
    fn target_dir_of(cmd: &Command) -> PathBuf {
        let args: Vec<_> = cmd.get_args().map(|a| a.to_string_lossy().into_owned()).collect();
        let at = args.iter().position(|a| a == "--target-dir");
        at.and_then(|i| args.get(i + 1))
            .map(PathBuf::from)
            .unwrap_or_else(|| panic!("names no --target-dir: {args:?}"))
    }

    /// The desktop release recipe and this list agree: whatever `just
    /// desktop::build-release` builds for a person to run is in the archive.
    #[test]
    fn the_pack_carries_what_the_desktop_release_builds() {
        let just = std::fs::read_to_string(workspace().join("just/desktop.just")).unwrap();
        let line = just
            .lines()
            .skip_while(|l| !l.starts_with("build-release:"))
            .nth(1)
            .expect("desktop.just has a build-release recipe");
        let built: Vec<&str> = line
            .split("--bin ")
            .skip(1)
            .filter_map(|p| p.split_whitespace().next())
            .collect();
        assert!(!built.is_empty());
        for b in built {
            assert!(
                BINS.contains(&b),
                "`desktop::build-release` builds `{b}` and the archive does not carry it"
            );
        }
        assert!(
            line.contains(FEATURES),
            "the archive's renderer is not the desktop release's: {line}"
        );
    }

    /// The loose files the pack copies exist in the tree, and the launcher and the
    /// installer name nothing that reaches a network.
    #[test]
    fn the_launcher_and_installer_exist_and_reach_no_network() {
        for f in LOOSE {
            let text = std::fs::read_to_string(workspace().join("infra/release").join(f))
                .unwrap_or_else(|e| panic!("infra/release/{f}: {e}"));
            if f.ends_with(".txt") {
                continue;
            }
            for word in ["curl", "wget", "http://", "https://", "nc ", "ssh "] {
                assert!(!text.contains(word), "infra/release/{f} names `{word}`");
            }
        }
    }

    #[test]
    fn a_listing_with_anything_extra_or_missing_is_refused() {
        let top = "kotton-abc-linux-x86_64";
        let good: String = expected_entries()
            .iter()
            .map(|e| format!("{top}/{e}\n"))
            .collect();
        assert!(check_entries(&format!("{top}/\n{top}/bin/\n{good}")).is_ok());

        let extra = format!("{good}{top}/.kotton.dev/keys/owner.key\n");
        assert!(check_entries(&extra).unwrap_err().contains("owner.key"));

        let missing: String = good
            .lines()
            .filter(|l| !l.ends_with("/kuid"))
            .map(|l| format!("{l}\n"))
            .collect();
        assert!(check_entries(&missing).is_err());

        // Outside the top directory: at the root, under a second top, through `..`,
        // and an empty directory the layout does not have.
        for planted in [
            "owner.key".to_string(),
            "elsewhere/owner.key".to_string(),
            format!("{top}/../owner.key"),
            format!("{top}/keys/"),
            format!("{top}/bin/kuid"),
        ] {
            let listing = format!("{top}/\n{good}{planted}\n");
            let err = check_entries(&listing).expect_err(&planted);
            assert!(err.contains(&planted), "{planted}: {err}");
        }
    }

    /// Every archive — the desktop's and both servers' — is refused without its
    /// `THIRD-PARTY-NOTICES`, by the same layout check its install test runs first.
    #[test]
    fn an_archive_without_its_third_party_notices_is_refused() {
        use crate::release_server::{RELAY, VAULT};
        for (top, expected) in [
            ("kotton-abc-linux-x86_64", expected_entries()),
            ("kotton-relay-abc-linux-x86_64", RELAY.entries()),
            ("kotton-vault-abc-linux-x86_64", VAULT.entries()),
        ] {
            assert!(expected.iter().any(|e| e == crate::license_check::FILE), "{top}");
            let without: String = expected
                .iter()
                .filter(|e| *e != crate::license_check::FILE)
                .map(|e| format!("{top}/{e}\n"))
                .collect();
            let err = check_layout(&without, &expected).unwrap_err();
            assert!(err.contains(crate::license_check::FILE), "{top}: {err}");
        }
    }

    /// Every archive — the desktop's and both servers' — names Kotton's own `LICENSE`
    /// and `NOTICES` at its top, and is refused without either by the layout check its
    /// install test runs first. The two are the repository root's, so the pack has them
    /// to copy.
    #[test]
    fn an_archive_without_kottons_own_license_or_notice_is_refused() {
        use crate::release_server::{RELAY, VAULT};
        for f in OWN {
            assert!(workspace().join(f).is_file(), "the repository root has no {f} to copy");
        }
        for (top, expected) in [
            ("kotton-abc-linux-x86_64", expected_entries()),
            ("kotton-relay-abc-linux-x86_64", RELAY.entries()),
            ("kotton-vault-abc-linux-x86_64", VAULT.entries()),
        ] {
            for f in OWN {
                assert!(expected.iter().any(|e| e == f), "{top} does not name {f} at its top");
                let without: String = expected
                    .iter()
                    .filter(|e| *e != f)
                    .map(|e| format!("{top}/{e}\n"))
                    .collect();
                let err = check_layout(&without, &expected).unwrap_err();
                assert!(err.contains(f), "{top} without {f}: {err}");
            }
        }
    }

    /// The desktop's `install.sh` keeps `LICENSE`, `NOTICES` and `THIRD-PARTY-NOTICES`
    /// in the prefix, byte for byte. Run on a stand-in tree, since what is under test is
    /// the script; `install_test` checks the same of a real archive.
    #[cfg(unix)]
    #[test]
    fn the_desktop_installer_keeps_kottons_license_and_notices_in_the_prefix() {
        let dir = tempfile::tempdir().unwrap();
        let tree = dir.path().join("kotton-abc-linux-x86_64");
        std::fs::create_dir_all(tree.join("bin")).unwrap();
        std::fs::create_dir_all(tree.join("share/kotton/shell")).unwrap();
        std::fs::write(tree.join("bin/kotton"), b"#!/bin/sh\n").unwrap();
        for f in ["install.sh", "kotton-start"] {
            std::fs::copy(workspace().join("infra/release").join(f), tree.join(f)).unwrap();
        }
        std::fs::write(tree.join("REVISION"), "abc\n").unwrap();
        std::fs::write(tree.join(crate::license_check::FILE), "stand-in notices\n").unwrap();
        for f in OWN {
            std::fs::copy(workspace().join(f), tree.join(f)).unwrap();
        }
        let prefix = dir.path().join("opt/kotton");
        let out = Command::new("/bin/sh")
            .arg(tree.join("install.sh"))
            .env_clear()
            .env("PATH", SYSTEM_PATH)
            .env("HOME", dir.path())
            .env("KOTTON_PREFIX", &prefix)
            .env("KOTTON_BINDIR", dir.path().join("bin"))
            .output()
            .unwrap();
        assert!(out.status.success(), "{}", said(&out));
        for f in OWN.iter().copied().chain([crate::license_check::FILE]) {
            assert_eq!(
                std::fs::read(prefix.join(f)).ok(),
                Some(std::fs::read(tree.join(f)).unwrap()),
                "install.sh did not keep {f} in the prefix"
            );
        }
    }

    /// A release served as the releases page serves one: a GET of `/<path>` answers the file
    /// at that path under `root`, or 404, and every path asked for is kept, in order.
    #[cfg(target_os = "linux")]
    fn serve(root: PathBuf) -> (u16, std::sync::Arc<std::sync::Mutex<Vec<String>>>) {
        use std::io::{Read as _, Write as _};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let asked = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let log = asked.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    match stream.read(&mut byte) {
                        Ok(1) => head.push(byte[0]),
                        _ => break,
                    }
                }
                let head = String::from_utf8_lossy(&head).to_string();
                let path = head.split_whitespace().nth(1).unwrap_or("/").trim_start_matches('/').to_string();
                log.lock().unwrap().push(path.clone());
                let inside = !path.split('/').any(|c| c.is_empty() || c == "..");
                let (status, body) = match inside.then(|| std::fs::read(root.join(&path)).ok()).flatten() {
                    Some(body) => ("200 OK", body),
                    None => ("404 Not Found", b"not found\n".to_vec()),
                };
                let _ = write!(stream, "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
                let _ = stream.write_all(&body);
            }
        });
        (port, asked)
    }

    /// **The checkout's `install.sh` installs only what the key at its tag signed.** Run as a
    /// person runs it — `git clone --depth 1 --branch <tag>`, then `sh kotton/install.sh` — from a
    /// clone of a stand-in repository whose root script is this tree's and whose
    /// `infra/release/allowed_signers` names a key made here, against a release served on
    /// loopback under `KOTTON_RELEASE_BASE`. The archives are stand-ins whose `install.sh`
    /// writes one file, since what is under test is the root script; `install_test` and
    /// `release-server-test` hold a real archive's own installer.
    ///
    /// It installs the desktop's archive, the relay's with `--kind relay`, handing the
    /// archive's installer the operator's key and the address, and the host's with
    /// `--kind host`, handing it a key each; a server's installer is told the command that
    /// reached it, the checkout's script and its kind, which stays after the script removes the
    /// directory the archive was unpacked in. It refuses, and installs
    /// nothing, on: an archive that is not the one `SHA256SUMS` names; a `SHA256SUMS` changed
    /// after it was signed; a signature by a key the tag does not hold, though the working copy
    /// and the page serving the release both name it; a release with no `SHA256SUMS.sig`,
    /// before the archive is downloaded; and a checkout not at a tag, before anything is.
    ///
    /// The stand-ins are named by the release's own [`archive_name`] and
    /// `release_server::archive_name`, packed as [`PACKED`] with their installer at
    /// [`ARCHIVE_INSTALLER`] under that top directory, so a rename in the release code fails
    /// here rather than at every real install. x86_64 only: the servers are built for no other.
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn the_checkouts_install_sh_installs_only_what_the_key_at_its_tag_signed() {
        for tool in ["git", "ssh-keygen", "sha256sum", "curl", "tar"] {
            let found = Command::new("sh").args(["-c", &format!("command -v {tool}")]).output().unwrap();
            assert!(found.status.success(), "{tool} is not on this machine, and this test runs the script that needs it");
        }
        let dir = tempfile::tempdir().unwrap();
        let at = |p: &str| dir.path().join(p);
        let run = |what: &str, cmd: &mut Command| {
            let out = cmd.output().unwrap_or_else(|e| panic!("{what}: {e}"));
            assert!(out.status.success(), "{what}: {}", said(&out));
            out
        };
        // Every tool with nothing of this machine's environment but its system PATH.
        let tool = |program: &str| {
            let mut c = Command::new(program);
            c.env_clear().env("PATH", SYSTEM_PATH).env("HOME", dir.path());
            c
        };

        // Two keys: the release's, which the tag names, and another.
        let signers = |key: &str| {
            let public = std::fs::read_to_string(at(&format!("{key}.pub"))).unwrap();
            format!("release@kotton namespaces=\"kotton-release\" {public}")
        };
        for key in ["release", "rogue"] {
            run(
                "ssh-keygen",
                tool("ssh-keygen").args(["-q", "-t", "ed25519", "-N", "", "-C", "release@kotton", "-f"]).arg(at(key)),
            );
        }

        // The repository at its tag, and a commit on main after it.
        let repo = crate::git_fixture::Repo::new();
        repo.write("install.sh", &std::fs::read_to_string(workspace().join("install.sh")).unwrap());
        repo.write("infra/release/allowed_signers", &signers("release"));
        let rev: String = repo.commit("the release").chars().take(12).collect();
        let tag = "v0.0.0-fixture";
        repo.git(&["tag", tag]);
        repo.write("after", "a commit after the tag\n");
        repo.commit("after the release");
        let clone = |branch: &str, into: &str| {
            run(
                "git clone",
                tool("git")
                    .args(["clone", "-q", "--depth", "1", "--branch", branch])
                    .arg(format!("file://{}", repo.path().display()))
                    .arg(at(into)),
            );
            at(into)
        };
        let kotton = clone(tag, "kotton");

        // The release: an archive for the desktop and one for the relay, named and laid out as
        // `release` and `release-server` name and lay out theirs, their sums, signed.
        let release = at("served").join(tag);
        std::fs::create_dir_all(&release).unwrap();
        let stage = at("stage");
        let pack = |name: &str, script: &str| {
            let tree = stage.join(name);
            std::fs::create_dir_all(&tree).unwrap();
            std::fs::write(tree.join(ARCHIVE_INSTALLER), script).unwrap();
            let file = format!("{name}{PACKED}");
            run("tar", tool("tar").arg("-czf").arg(release.join(&file)).arg("-C").arg(&stage).arg(name));
            file
        };
        let desktop = pack(
            &archive_name(&Revision { sha: rev.clone(), dirty: false }),
            "#!/bin/sh\nset -eu\nmkdir -p \"$KOTTON_PREFIX\"\necho desktop > \"$KOTTON_PREFIX/installed\"\necho \"the stand-in installed into $KOTTON_PREFIX\"\n",
        );
        let relay = pack(
            &crate::release_server::archive_name(crate::release_server::RELAY.name, &rev, true, crate::release_server::TARGET),
            "#!/bin/sh\nset -eu\nmkdir -p \"$KOTTON_PREFIX\"\necho \"relay $KOTTON_OPERATOR_KEY $KOTTON_PUBLIC_ADDR $KOTTON_INSTALL_COMMAND\" > \"$KOTTON_PREFIX/installed\"\n",
        );
        let host = pack(
            &crate::release_server::archive_name(crate::release_server::HOST, &rev, true, crate::release_server::TARGET),
            "#!/bin/sh\nset -eu\nmkdir -p \"$KOTTON_PREFIX\"\necho \"host $KOTTON_OPERATOR_KEY_RELAY $KOTTON_OPERATOR_KEY_VAULT $KOTTON_INSTALL_COMMAND\" > \"$KOTTON_PREFIX/installed\"\n",
        );
        let sums = run(
            "sha256sum",
            tool("sha256sum").args([&desktop, &relay, &host]).current_dir(&release),
        );
        std::fs::write(release.join("SHA256SUMS"), &sums.stdout).unwrap();
        let sign = |key: &str| {
            let _ = std::fs::remove_file(release.join("SHA256SUMS.sig"));
            run(
                "ssh-keygen -Y sign",
                tool("ssh-keygen").args(["-q", "-Y", "sign", "-n", "kotton-release", "-f"]).arg(at(key)).arg(release.join("SHA256SUMS")),
            );
        };
        sign("release");

        let (port, asked) = serve(at("served"));
        let base = format!("http://127.0.0.1:{port}");
        let mut runs = 0;
        let mut install = |checkout: &Path, args: &[&str]| {
            runs += 1;
            let prefix = at(&format!("prefix-{runs}"));
            asked.lock().unwrap().clear();
            let out = Command::new("/bin/sh")
                .arg(checkout.join("install.sh"))
                .args(args)
                .env_clear()
                .env("PATH", SYSTEM_PATH)
                .env("HOME", dir.path())
                .env("TMPDIR", dir.path())
                .env("KOTTON_RELEASE_BASE", &base)
                .env("KOTTON_PREFIX", &prefix)
                .env("KOTTON_OPERATOR_KEY", "07ab")
                .env("KOTTON_OPERATOR_KEY_RELAY", "07cd")
                .env("KOTTON_OPERATOR_KEY_VAULT", "07ef")
                .env("KOTTON_PUBLIC_ADDR", "203.0.113.7")
                .output()
                .unwrap();
            let installed = std::fs::read_to_string(prefix.join("installed")).ok();
            (out, installed, std::mem::take(&mut *asked.lock().unwrap()))
        };
        let from = |files: &[&str]| files.iter().map(|f| format!("{tag}/{f}")).collect::<Vec<_>>();
        let refused = |out: &std::process::Output, installed: &Option<String>, why: &str| {
            let err = String::from_utf8_lossy(&out.stderr);
            assert!(!out.status.success() && err.contains(why) && err.contains("nothing was installed"), "expected `{why}`: {}", said(out));
            assert_eq!(installed, &None, "a refused install ran the archive's install.sh: {}", said(out));
        };

        // A dry run says the tag's URLs and asks for none of them.
        let (out, installed, got) = install(&kotton, &["--dry-run"]);
        assert!(out.status.success(), "{}", said(&out));
        assert!(String::from_utf8_lossy(&out.stdout).contains(&format!("{base}/{tag}/{desktop}")), "{}", said(&out));
        assert_eq!((installed, got), (None, vec![]));

        // The desktop, from a good release: the sums and their signature, then the archive.
        let (out, installed, got) = install(&kotton, &[]);
        assert!(out.status.success(), "{}", said(&out));
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(stdout.contains("Good \"kotton-release\" signature for release@kotton"), "{}", said(&out));
        assert!(stdout.contains("the stand-in installed into"), "the archive's install.sh did not speak: {}", said(&out));
        assert_eq!(installed.as_deref(), Some("desktop\n"));
        assert_eq!(got, from(&["SHA256SUMS", "SHA256SUMS.sig", &desktop]));
        assert!(
            std::fs::read_dir(dir.path()).unwrap().flatten().all(|e| !e.file_name().to_string_lossy().starts_with("kotton-install.")),
            "the download directory was left behind"
        );

        // The relay, as root runs it on a host: the operator's key and the address reach its installer.
        let (out, installed, got) = install(&kotton, &["--kind", "relay"]);
        assert!(out.status.success(), "{}", said(&out));
        let script = kotton.join("install.sh");
        assert_eq!(installed, Some(format!("relay 07ab 203.0.113.7 sh {} --kind relay\n", script.display())));
        assert_eq!(got, from(&["SHA256SUMS", "SHA256SUMS.sig", &relay]));

        // The host, the relay and the vault in one archive, by the name the release gives it,
        // each instance's key reaching its installer; the command to run again is the script's.
        let (out, installed, got) = install(&kotton, &["--kind", "host"]);
        assert!(out.status.success(), "{}", said(&out));
        assert_eq!(installed, Some(format!("host 07cd 07ef sh {} --kind host\n", script.display())));
        assert_eq!(got, from(&["SHA256SUMS", "SHA256SUMS.sig", &host]));
        assert!(script.exists(), "the command to run again names a script that is gone");

        // An archive that is not the one the sums name.
        let good = std::fs::read(release.join(&desktop)).unwrap();
        let mut tampered = good.clone();
        tampered.extend_from_slice(b"\0");
        std::fs::write(release.join(&desktop), &tampered).unwrap();
        let (out, installed, _) = install(&kotton, &[]);
        refused(&out, &installed, "is not the file SHA256SUMS names, and nothing from it runs");

        // And the sums changed to name it, after they were signed.
        let signed = std::fs::read_to_string(release.join("SHA256SUMS")).unwrap();
        let digest = run("sha256sum", tool("sha256sum").arg(&desktop).current_dir(&release));
        let forged: String = signed
            .lines()
            .map(|l| if l.ends_with(&desktop) { String::from_utf8_lossy(&digest.stdout).trim_end().to_string() } else { l.to_string() })
            .map(|l| l + "\n")
            .collect();
        assert_ne!(forged, signed);
        std::fs::write(release.join("SHA256SUMS"), &forged).unwrap();
        let (out, installed, got) = install(&kotton, &[]);
        refused(&out, &installed, "is not a good signature by the key infra/release/allowed_signers holds at");
        assert_eq!(got, from(&["SHA256SUMS", "SHA256SUMS.sig"]), "the archive was downloaded under a bad signature");

        // Signed again by another key, which the working copy names and the page serves beside
        // the release: neither is the key the tag holds.
        sign("rogue");
        std::fs::write(release.join("allowed_signers"), signers("rogue")).unwrap();
        let edited = clone(tag, "kotton-edited");
        std::fs::write(edited.join("infra/release/allowed_signers"), signers("rogue")).unwrap();
        let (out, installed, _) = install(&edited, &[]);
        refused(&out, &installed, "is not a good signature by the key infra/release/allowed_signers holds at");

        // The release restored, and its signature taken away.
        std::fs::write(release.join(&desktop), &good).unwrap();
        std::fs::write(release.join("SHA256SUMS"), &signed).unwrap();
        sign("release");
        let (out, _, _) = install(&kotton, &[]);
        assert!(out.status.success(), "the restored release: {}", said(&out));
        std::fs::remove_file(release.join("SHA256SUMS.sig")).unwrap();
        let (out, installed, got) = install(&kotton, &[]);
        refused(&out, &installed, "A release with no SHA256SUMS.sig has not been signed, and nothing from it runs.");
        assert_eq!(got, from(&["SHA256SUMS", "SHA256SUMS.sig"]), "the archive was downloaded for an unsigned release");

        // Off a tag, nothing is asked for at all, and the refusal says how to get one.
        sign("release");
        let main = clone("main", "kotton-main");
        for args in [&[][..], &["--dry-run"]] {
            let (out, installed, got) = install(&main, args);
            refused(&out, &installed, "this checkout is not at a release tag");
            assert!(String::from_utf8_lossy(&out.stderr).contains("git clone --depth 1 --branch <tag>"), "{}", said(&out));
            assert_eq!(got, Vec::<String>::new());
        }
    }

    #[test]
    fn a_link_or_a_device_is_refused_whatever_its_name() {
        let ok = "drwxr-xr-x u/g 0 2026-09-25 18:00 top/\n-rwxr-xr-x u/g 9 2026-09-25 18:00 top/bin/kuid\n";
        assert!(check_entry_types(ok).is_ok());
        for odd in [
            "lrwxrwxrwx u/g 0 2026-09-25 18:00 top/bin/kotton-runner -> /tmp/evil",
            "hrwxr-xr-x u/g 0 2026-09-25 18:00 top/bin/kuid link to top/bin/kotton",
        ] {
            let err = check_entry_types(&format!("{ok}{odd}\n")).unwrap_err();
            assert!(err.contains("kotton-runner") || err.contains("link to"), "{err}");
        }
    }
}
