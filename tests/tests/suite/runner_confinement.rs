// SPDX-License-Identifier: AGPL-3.0-or-later
//! The runner is confined by the operating system, and not only by wasmtime.
//!
//! `TASK-the-wasm-runner-is-confined-only-by-wasmtime` found `kuserd` spawning
//! the process that executes untrusted third-party WASM with a bare
//! `tokio::process::Command::new(runner)` — pipes, `kill_on_drop`, and nothing
//! else. The whole confinement of a guest app rested on one implementation
//! having no escapes, which is a good bet and a single bet.
//!
//! **The two sandboxes are different mechanisms.** WASM confines by
//! construction: a guest cannot name a syscall because the linker never
//! provided one. The operating system confines by interception: native code
//! Kotton did not write asks the kernel, and the kernel refuses. What is
//! measured here is the second one, and it is measured on the process rather
//! than on the guest — *"even when the guest inside it is doing nothing at
//! all"*, which is that record's own phrasing and the reason the first two
//! tests below answer before any component is instantiated.
//!
//! The first three run the daemon's own `confine_runner`, not a copy of it. A
//! profile exercised only by a re-implementation of itself proves the
//! re-implementation — the same reasoning that made `supervise_kinferd` public
//! for `inference_sidecar`.
//!
//! **The last two prove what the first three cannot: that the daemon's spawn
//! paths ask for the confinement at all.** They launch through `app_launch`,
//! one app per spawn path — `spawn_runner` for a one-shot app,
//! `open_long_lived_runner` for a long-lived one and the occupant — and read
//! back what the kernel told the process the daemon spawned. Until 2026-09-23
//! this file said every other app test in the suite held that half by passing.
//! Measured that day it did not: an unconfined runner does everything a
//! confined one does, so deleting a `confine_runner` call left them green.
//!
//! On a platform `core/proc` has no provider for, the runner keeps wasmtime as
//! its only layer and these tests fail — which is the true answer for that
//! platform, and the question escalated on
//! `TASK-windows-cannot-confine-a-guest-so-kotton-will-not-run-one-there`.

use crate::common::{mock_runner_bin, runner_bin};
use kotton_app::daemon::apps::{confine_runner, runner_profile};
use kotton_wire::{RunnerInput, RunnerOp, RunnerOutput};
use std::path::{Path, PathBuf};
use std::process::Stdio;

/// The probe could open a socket. The sandbox is not doing its job.
///
/// Not 0, because 0 is what a mock runner that does not know `probe-socket`
/// exits with — measured on the landing, 2026-09-23, when a binary built before
/// the merge failed this test as an open socket. A stale probe now fails as a
/// broken probe, which is what it is. It includes a refused *connection*,
/// because that is a socket the kernel created and carried a SYN for.
const EXIT_ALLOWED: i32 = 2;
/// The kernel refused it.
const EXIT_REFUSED: i32 = 3;

/// A component and a manifest that are real, so the runner gets as far as
/// anything it is asked to open.
fn probe_app() -> (String, PathBuf) {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/probe-app");
    let manifest = std::fs::read_to_string(dir.join("manifest.toml")).expect("probe manifest");
    let wasm = dir.join("app.wasm");
    assert!(
        wasm.exists(),
        "the probe component is not built, so this test cannot confine a real runner.\n  \
         missing: {}\n  fix:     cargo xtask build-apps",
        wasm.display()
    );
    (manifest, wasm)
}

fn input(manifest_toml: String, wasm_path: &Path, data_root: &Path) -> RunnerInput {
    RunnerInput {
        manifest_toml,
        wasm_path: wasm_path.to_string_lossy().into_owned(),
        app_data_path: data_root
            .join("app_data")
            .join("probe.db")
            .to_string_lossy()
            .into_owned(),
        approved: vec![],
        envelopes: vec![],
        revoked_ids: vec![],
        trusted_issuers: vec![],
        kel_keys: vec![],
        user_vfs_path: None,
        roots: None,
        occupant: false,
        op: RunnerOp::Launch {
            launch_args: vec![],
            surface: kotton_wire::SurfaceHandle::mint(),
        },
    }
}

/// A runner process, spawned under the profile `grant` describes, asked to do
/// `fed`. Returns what it wrote back.
async fn confined_runner(grant: &RunnerInput, fed: &RunnerInput) -> RunnerOutput {
    use tokio::io::AsyncWriteExt as _;

    let runner = Path::new(runner_bin());
    let mut cmd = tokio::process::Command::new(runner);
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    confine_runner(&mut cmd, runner, grant)
        .await
        .expect("the daemon's own profile is enforceable on this kernel");

    let mut child = cmd.spawn().expect("the confined runner started");
    {
        let mut stdin = child.stdin.take().expect("stdin was piped");
        let line = serde_json::to_vec(fed).expect("serialize");
        stdin.write_all(&line).await.expect("write");
        stdin.write_all(b"\n").await.expect("newline");
        stdin.flush().await.expect("flush");
    }
    let out = child.wait_with_output().await.expect("the runner finished");
    if !out.stderr.is_empty() {
        eprintln!(
            "confined runner stderr: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "the runner wrote no frame this test could read ({e}); stdout was: {}",
            String::from_utf8_lossy(&out.stdout)
        )
    })
}

/// The reach a runner is given is the component it was handed, so a component
/// somewhere else is not openable — by the same process, in the same spawn,
/// differing only in which path it was asked for.
#[tokio::test]
async fn a_runner_cannot_read_a_component_outside_its_grant() {
    let (manifest, wasm) = probe_app();
    let granted = tempfile::tempdir().expect("granted dir");
    let elsewhere = tempfile::tempdir().expect("ungranted dir");

    let in_grant = granted.path().join("app.wasm");
    let out_of_grant = elsewhere.path().join("app.wasm");
    std::fs::copy(&wasm, &in_grant).expect("copy the component into the grant");
    std::fs::copy(&wasm, &out_of_grant).expect("copy the component outside it");

    let grant = input(manifest.clone(), &in_grant, granted.path());

    // The control. Same profile, and the component it names: the runner reads
    // it. Without this the assertion below would pass just as well against a
    // runner that could not read anything at all.
    let allowed = confined_runner(&grant, &grant).await;
    match &allowed {
        // The confined runner read the component, opened and migrated the
        // SQLite database beneath its data grant, and got as far as
        // instantiating the guest — where it stopped because this input
        // approves nothing, which is `confinement.rs`'s subject and not this
        // one's. Asserted precisely rather than as "no permission error",
        // because a control that only says what did *not* happen passes just
        // as well when the runner fell over at its first line.
        RunnerOutput::Error { message } => assert!(
            message.contains("a matching implementation was not found in the linker"),
            "the confined runner did not reach instantiation; it said: {message}"
        ),
        other => panic!("expected the linker refusal an unapproved app gets, got {other:?}"),
    }

    // The same process, asked for the identical bytes at a path nobody granted.
    let denied = confined_runner(
        &grant,
        &input(manifest, &out_of_grant, granted.path()),
    )
    .await;
    match denied {
        RunnerOutput::Error { message } => assert!(
            message.contains("read wasm") && message.contains("denied"),
            "expected the kernel to refuse the read, got: {message}"
        ),
        other => panic!("a component outside the grant was reachable: {other:?}"),
    }
}

/// A runner process, before it has read a frame, let alone instantiated a
/// guest, cannot obtain a socket.
///
/// The probe is the mock runner because the assertion needs a process that
/// *tries*, and the real runner has no code that would — which is the point:
/// what is being measured is the confinement the daemon applies to whatever it
/// spawns as a runner, not a property of one binary's source.
#[tokio::test]
async fn a_runner_process_cannot_open_a_socket_with_no_guest_in_it_at_all() {
    let (manifest, wasm) = probe_app();
    let dir = tempfile::tempdir().expect("dir");
    let grant = input(manifest, &wasm, dir.path());

    let runner = Path::new(mock_runner_bin());
    let mut cmd = tokio::process::Command::new(runner);
    cmd.env("MOCK_RUNNER_MODE", "probe-socket")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    confine_runner(&mut cmd, runner, &grant)
        .await
        .expect("the daemon's own profile is enforceable on this kernel");

    let out = cmd.output().await.expect("the probe ran");
    if !out.stderr.is_empty() {
        eprintln!(
            "probe stderr: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    let code = out.status.code().expect("the probe exited rather than being signalled");
    assert_ne!(
        code, EXIT_ALLOWED,
        "a runner process opened a TCP socket; Article VIII says no app reaches the network \
         directly and DEC-0074 says the process running its code is confined like a guest"
    );
    assert_eq!(
        code, EXIT_REFUSED,
        "the socket did not open, and not because it was refused — the probe reported {code}, \
         which is a test that cannot tell confinement from a broken probe"
    );
}

/// Each root the occupant is handed is readable by the runner that holds it,
/// writable only where the host handed it writable, nothing about a root that
/// is not on disk is granted, and an app that is not the occupant is granted no
/// root tree at all.
///
/// `roots.tree` turns a `RunnerRoot` into a directory handle on its
/// `tree_path`, and a root other than the personal one keeps its tree at
/// `roots/<id>` — beside the VFS mount, not inside it. Without a grant per
/// root the kernel refuses the listing, and the file browser's sidebar shows a
/// root it cannot open. That arrived on `main` after the sandbox was written,
/// so this is the test that holds the two together.
///
/// **The reach follows `RunnerRoot::writable`** since
/// `TASK-a-member-writes-in-a-roots-tree`: the field the sandbox's handle reads
/// is the field the kernel profile reads. The host hands every root read-only
/// until the owner rules whether the occupant may write one on its designation
/// alone, so `fam` below is the shape of every root today and `ours` is the
/// shape a yes would produce — the mechanism, asserted so the two layers
/// cannot drift apart when the answer comes.
///
/// Asserted on the profile rather than on a spawned process: what a grant lets
/// the kernel do is `core/proc`'s `tests/sandbox.rs`, measured there against
/// Landlock. What is asserted here is that the daemon asks for it.
#[tokio::test]
async fn the_occupant_may_read_each_root_it_is_handed_and_nothing_else() {
    use kotton_proc::{Grant, Reach};
    use kotton_wire::runner::{RunnerKeeping, RunnerResidency, RunnerRoot};

    let (manifest, wasm) = probe_app();
    let dir = tempfile::tempdir().expect("dir");
    let roots_dir = dir.path().join("users").join("u").join("roots");
    let on_disk = roots_dir.join("fam");
    let written = roots_dir.join("ours");
    std::fs::create_dir_all(&on_disk).expect("the store made this root's tree");
    std::fs::create_dir_all(&written).expect("and this one");
    let not_on_disk = roots_dir.join("gone");

    let root = |id: &str, tree: &Path, writable: bool| RunnerRoot {
        id: id.to_string(),
        name: id.to_string(),
        members: vec![],
        targets: vec![],
        residency: RunnerResidency::Full,
        kept: RunnerKeeping::ThisDeviceOnly,
        tree_path: tree.to_string_lossy().into_owned(),
        granted: false,
        writable,
    };
    let mut occupant = input(manifest.clone(), &wasm, dir.path());
    occupant.occupant = true;
    occupant.roots = Some(kotton_wire::runner::RunnerRoots::Read(vec![
        root("fam", &on_disk, false),
        root("ours", &written, true),
        root("gone", &not_on_disk, false),
    ]));

    let runner = Path::new(runner_bin());
    let profile = runner_profile(runner, &occupant).await.expect("a profile");
    let grants = profile.grants();

    assert!(
        grants.contains(&Grant { path: on_disk.clone(), reach: Reach::Read }),
        "a root the occupant holds is not readable by its runner; grants were {grants:?}"
    );
    assert!(
        !grants.iter().any(|g| g.path == on_disk && g.reach != Reach::Read),
        "a root handed read-only was granted more than read in the kernel: {grants:?}"
    );
    assert!(
        grants.contains(&Grant { path: written.clone(), reach: Reach::Write }),
        "a root the host handed writable is not writable in the kernel, so the two layers \
         disagree: {grants:?}"
    );
    assert!(
        !grants.iter().any(|g| g.path == not_on_disk),
        "a root with no tree on disk was granted, which a profile cannot do without \
         widening to whichever ancestor exists: {grants:?}"
    );

    // And the profile is still enforceable with the roots in it, which is the
    // assertion that fails if a grant named something the kernel will not take.
    let mut cmd = tokio::process::Command::new(runner);
    confine_runner(&mut cmd, runner, &occupant)
        .await
        .expect("the occupant's profile, roots and all, is enforceable on this kernel");

    // An ordinary app on the same machine: the daemon hands it no roots, so
    // its runner is granted nothing in any root's tree, read or write.
    let guest = input(manifest, &wasm, dir.path());
    assert!(guest.roots.is_none() && !guest.occupant, "the fixture is an ordinary app");
    let guest_grants = runner_profile(runner, &guest).await.expect("a profile").grants().to_vec();
    assert!(
        !guest_grants.iter().any(|g| g.path.starts_with(&roots_dir)),
        "an app that is not the occupant was granted a root's tree: {guest_grants:?}"
    );
}

/// **A runner launched for a person is granted nothing in their tree.**
///
/// It was granted all of `users/<uid>/data`, writable, because it answered
/// `files` calls with `tokio::fs` there — which put a guest's bytes into the
/// sealed store's own directory in the clear
/// (`TASK-a-file-an-app-writes-rests-in-the-clear-in-the-sealed-stores-own-directory`).
/// It asks the daemon for every file now, so the grant is gone rather than
/// narrowed, and an escaped runner reaches the person's files only through
/// the daemon's check against its grant. The live half — a real runner under
/// this profile writing and reading through its handle — is
/// `guest_files::a_file_an_app_writes_rests_sealed_and_packs_and_reads_back`.
#[tokio::test]
async fn a_runner_is_granted_nothing_in_the_persons_tree() {
    let (manifest, wasm) = probe_app();
    let dir = tempfile::tempdir().expect("dir");
    let data = dir.path().join("users").join("u").join("data");
    std::fs::create_dir_all(&data).expect("the store made the person's directory");

    let mut launched = input(manifest, &wasm, dir.path());
    launched.user_vfs_path = Some(data.to_string_lossy().into_owned());
    let runner = Path::new(runner_bin());
    let profile = runner_profile(runner, &launched).await.expect("a profile");
    let grants = profile.grants();
    assert!(
        !grants.iter().any(|g| g.path.starts_with(&data) || data.starts_with(&g.path)),
        "the runner's kernel profile reaches the person's tree: {grants:?}"
    );
}

/// Launch an installed app through the daemon's own `app_launch`, with the
/// mock runner told to try a socket and paint what the kernel said.
///
/// Serial because `MOCK_RUNNER_MODE` is process-wide, as in `app_long_lived`.
#[allow(unsafe_code)] // env::set_var/remove_var are unsafe in Rust 1.81+; callers are #[serial]
async fn what_a_launched_runner_was_told_about_a_socket(manifest: &str) -> String {
    use crate::common::{InstallApprovingAll as _, TestEnv};

    // SAFETY: every caller is `#[serial_test::serial]`, so nothing else runs.
    unsafe { std::env::set_var("MOCK_RUNNER_MODE", "report-socket") };
    let mut env = TestEnv::spawn_with_mock_runner().await;
    env.client
        .create_user("owner", crate::common::TEST_PASSPHRASE)
        .await
        .expect("create_user (authenticates the connection)");
    let (app_id, _name, _caps) = env
        .client
        .app_install_approving_all(
            "",
            manifest.to_string(),
            vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00],
        )
        .await
        .expect("app_install");
    let launched = env.client.app_launch(&app_id, vec![]).await;
    unsafe { std::env::remove_var("MOCK_RUNNER_MODE") };

    let patches = launched.expect("app_launch").patches;
    let patch = patches
        .first()
        .expect("the probe paints its verdict as the launch's patch");
    let report: serde_json::Value = serde_json::from_slice(&patch[1..])
        .expect("the probe paints raw JSON (format version 0x00)");
    report["socket"]
        .as_str()
        .expect("the report names what the kernel said")
        .to_string()
}

/// **The one-shot spawn applies the confinement** — `spawn_runner`, reached
/// through `app_launch` for an app whose manifest is not long-lived.
///
/// The tests above drive `confine_runner` on a command this file built, which
/// proves the profile and not that the daemon asks for it; the module comment
/// says what was measured when that half was left to the rest of the suite.
#[tokio::test]
#[serial_test::serial]
async fn a_runner_the_daemon_launches_one_shot_cannot_open_a_socket() {
    let verdict = what_a_launched_runner_was_told_about_a_socket(
        r#"
[app]
id      = "sh.kotton.test-confined-one-shot"
name    = "Confined One-Shot"
version = "0.1.0"
"#,
    )
    .await;
    assert_eq!(
        verdict, "refused",
        "a runner spawned by `app_launch` through `spawn_runner` was not refused a socket"
    );
}

/// **The long-lived spawn applies the confinement** — `open_long_lived_runner`,
/// which is where every occupant and every long-lived app is spawned, and which
/// main rewrote after the sandbox was cut (the surface list handed back on
/// failure). Mutation-checked the same way as the one above.
#[tokio::test]
#[serial_test::serial]
async fn a_runner_the_daemon_launches_long_lived_cannot_open_a_socket() {
    let verdict = what_a_launched_runner_was_told_about_a_socket(
        r#"
[app]
id      = "sh.kotton.test-confined-long-lived"
name    = "Confined Long-Lived"
version = "0.1.0"
kind    = "long-lived"
"#,
    )
    .await;
    assert_eq!(
        verdict, "refused",
        "a runner spawned by `app_launch` through `open_long_lived_runner` was not refused a socket"
    );
}

/// **An occupant the person approved only to read its files cannot write them
/// by any door** — the assessor's probe of 2026-09-23, run end to end
/// (`TASK-a-member-writes-in-a-roots-tree`).
///
/// The unit tests hold each half on its own side of the process boundary:
/// `personal_is_listed_with_no_tree_so_its_files_have_one_door` and
/// `no_root_is_handed_writable_until_the_owner_rules` in `kuserd` show what the
/// host hands over, `a_read_only_occupant_cannot_write_its_files_through_the_personal_root`
/// in `core/wasm` shows what the sandbox does with it. Neither crate can hold
/// the other's half, so neither can see them drift apart. This can: a real
/// daemon, a real person with a real store, the real confined runner, and a
/// component (`tests/fixtures/roots-probe`) that is designated the occupant
/// with `files.read = ["/"]` and nothing else, then tries the granted handle
/// and every root's tree against a file the test seeded, and paints what each
/// door answered.
///
/// Designating it needs nothing — `app_set_role("shell", id)` asks for no
/// capability — which is why this is the shape of the attack and not a
/// contrivance: any installed app can be made the occupant.
///
/// The control is the roots list itself: *Personal* must be in it, or the
/// interface was not linked and every refusal below would be the linker's.
#[tokio::test]
async fn a_read_only_occupant_cannot_write_its_files_by_any_door() {
    use crate::common::{InstallApprovingAll as _, TestEnv, TEST_PASSPHRASE};

    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/roots-probe");
    let manifest = std::fs::read_to_string(fixture.join("manifest.toml")).expect("manifest");
    let wasm_path = fixture.join("app.wasm");
    let wasm = std::fs::read(&wasm_path).unwrap_or_else(|e| {
        panic!(
            "the roots probe is not built, so this test cannot run the occupant.\n  \
             missing: {} ({e})\n  fix:     cargo xtask build-apps",
            wasm_path.display()
        )
    });

    let mut env = TestEnv::spawn_with_real_runner().await;
    env.client
        .create_user("owner", TEST_PASSPHRASE)
        .await
        .expect("create_user (authenticates the connection)");
    // Seeded through the store, where the person's files are: the granted
    // handle is answered from it, and a file planted in `data/` by hand would
    // be a plaintext file the store cannot see
    // (`TASK-a-file-an-app-writes-rests-in-the-clear-in-the-sealed-stores-own-directory`).
    env.client
        .write_file("owner", "/mine.md", b"orig")
        .await
        .expect("seed the person's file");

    let (app_id, _, _) = env
        .client
        .app_install_approving_all("owner", manifest, wasm)
        .await
        .expect("install, approving the one grant it asks for: files.read on /");
    env.client
        .app_set_role("shell", &app_id)
        .await
        .expect("designating an installed app asks for nothing");

    let patches = match env.client.app_launch(&app_id, vec![]).await {
        Ok(launched) => launched.patches,
        Err(e) => panic!("the designated probe did not launch: {e}"),
    };
    let patch = patches.first().expect("the probe paints its report as the launch's patch");
    let report: serde_json::Value =
        serde_json::from_slice(&patch[1..]).expect("the probe paints raw JSON (format version 0x00)");
    eprintln!("roots probe report: {report}");

    // The control: the roots interface is linked and the granted root — the
    // one first run laid over the person's files, *This PC* — is listed, and
    // the host says which one it is rather than the probe matching a name
    // (`TASK-this-pc-is-the-one-root-everyone-starts-with`).
    let rows = report["roots"].as_array().expect("a roots list");
    let granted: Vec<&serde_json::Value> = rows.iter().filter(|r| r["granted"] == true).collect();
    assert_eq!(granted.len(), 1, "exactly one root is the granted tree: {report}");
    let personal = granted[0];
    assert_eq!(personal["name"], "This PC", "the granted root is the one first run named: {report}");

    // Door one: the granted handle is read-only and refuses.
    assert_eq!(report["granted_handles"], 1, "{report}");
    assert_eq!(report["granted_writable"], false, "{report}");
    assert!(report["granted_write"].as_str().unwrap_or("").starts_with("err"), "{report}");

    // Door two: Personal has no tree, and no root anywhere accepted the write.
    assert!(
        personal["tree"].as_str().unwrap_or("").starts_with("err"),
        "roots.tree handed the occupant a handle on the VFS mount: {report}"
    );
    for row in rows {
        assert_ne!(row["write"], "ok", "a root's tree accepted a write on designation alone: {report}");
    }

    assert_eq!(
        env.client.read_file("owner", "/mine.md").await.expect("the file is still there"),
        b"orig",
        "a read-only occupant wrote the person's file: {report}"
    );
}
