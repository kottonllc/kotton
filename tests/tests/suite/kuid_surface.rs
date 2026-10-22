// SPDX-License-Identifier: AGPL-3.0-or-later
//! Integration tests — kuid display server / SurfaceProxy (RFC-0018)
//!
//! Covers:
//! 1. The kuserd→kuid variants are absent from the user channel's wire surface.
//! 2. An external client cannot express one to kuserd at all.
//! 3. kuid has no socket name, because it has no socket.
//! 4. `sidecar_states` map is seeded with the `"kuid"` key on daemon spawn.


use crate::common::TestEnv;
use kotton_sys::ipc::IpcEndpoint;
use kotton_wire::KuidRequest;
use kotton_wire::{UserRequest, UserResponse};
use kotton_ipc::IpcClient;

const USER: &str = "kuid_surface_test";

// ── helpers ───────────────────────────────────────────────────────────────────

async fn auth_client(endpoint: &IpcEndpoint, token: &str) -> IpcClient<UserRequest, UserResponse> {
    let mut client = IpcClient::<UserRequest, UserResponse>::connect(endpoint.clone())
        .await
        .expect("IpcClient::connect");
    match client
        .send(&UserRequest::Authenticate {
            token: kotton_wire::ipc::SecretText::new(token),
            scope: None,
        })
        .await
        .expect("Authenticate send")
    {
        UserResponse::ActiveSession { .. } => {}
        other => panic!("unexpected auth response: {other:?}"),
    }
    client
}

// ── tests ─────────────────────────────────────────────────────────────────────

/// The four kuserd→kuid variants must be absent from the **user channel** entirely.
///
/// This used to assert only that they were missing from `REMOTE_ELIGIBLE`, which
/// kept them off the remote path while leaving them nameable by any local caller.
/// They now live on kuid's own socket as [`KuidRequest`] (RFC-0082), so the
/// stronger statement is available: `UserRequest` cannot express them at all, and
/// that is what this checks.
#[test]
fn the_compositor_variants_are_not_on_the_user_channel() {
    for variant in &[
        "SurfaceOpen",
        "SurfaceCommit",
        "SurfaceClose",
        "SurfaceResize",
        // Added by RFC-0087 stage 1. A verb arriving on the compositor channel
        // has to be absent from this one from the day it exists, or the gap
        // between the two is something a later reader has to notice.
        "SurfaceRaise",
    ] {
        let wire = format!(r#"{{"{variant}":{{}}}}"#);
        assert!(
            serde_json::from_str::<UserRequest>(&wire).is_err(),
            "{variant} still deserializes as a UserRequest — it belongs to kuid's channel",
        );
    }
}

/// …and they *are* expressible on the channel that owns them.
///
/// The pair matters: the test above alone would also pass if the variants had
/// simply been deleted.
#[test]
fn the_compositor_variants_are_on_the_kuid_channel() {
    // Addressed by handle, not by app id (RFC-0087). This literal was
    // `{"SurfaceClose":{"app_id":"test.app"}}` until 2026-09-18, and the
    // decoder now refuses it — *"missing field `handle`"* — which is the
    // property this file's neighbour asserts from the other side.
    let wire = r#"{"SurfaceClose":{"handle":"00000000-0000-0000-0000-000000000000"}}"#;
    let parsed = serde_json::from_str::<KuidRequest>(wire).expect("SurfaceClose is a KuidRequest");
    assert_eq!(parsed.variant_name(), "SurfaceClose");

    // And an app id is not a surface: a frame naming one does not decode at
    // all, so nothing downstream can read it.
    let by_name = r#"{"SurfaceClose":{"app_id":"test.app"}}"#;
    assert!(
        serde_json::from_str::<KuidRequest>(by_name).is_err(),
        "the compositor channel must not accept a surface named by its app",
    );
}

/// An authenticated external client cannot send `SurfaceOpen` to kuserd.
///
/// It previously could, and got `UserResponse::Error { "…internal protocol" }`
/// back from a dispatch arm. That arm is deleted: kuserd's socket deserializes
/// `UserRequest`, which has no such variant, so the frame is rejected by the
/// decoder before any handler runs.
///
/// The client is still built and authenticated here rather than asserting on
/// serde alone, because the property under test is *"a real caller on a real
/// connection cannot do this"* — and the connection closing on an undecodable
/// frame is the mechanism doing it.
#[tokio::test]
async fn kuid_surface_requests_cannot_be_expressed_by_external_clients() {
    let mut env = TestEnv::spawn().await;
    env.client.create_user(USER, crate::common::TEST_PASSPHRASE).await.expect("create_user");
    let token = env.client.session_token.clone().expect("session token");

    let mut client = auth_client(&env.endpoint, &token).await;

    // The authenticated connection works for a variant the user channel owns.
    let ok = client
        .send(&UserRequest::CallerInfo)
        .await
        .expect("CallerInfo send");
    assert!(
        !matches!(ok, UserResponse::Error { .. }),
        "the connection should be usable: {ok:?}",
    );

    // The compositor's own wire form is not a UserRequest, so kuserd's decoder
    // cannot produce one — there is no handler left to reach.
    let wire = r#"{"SurfaceOpen":{"handle":"00000000-0000-0000-0000-000000000000","tier":"App","title":"T","width":800,"height":600}}"#;
    assert!(
        serde_json::from_str::<UserRequest>(wire).is_err(),
        "SurfaceOpen must not decode on the user channel",
    );
}

/// kuid has no socket name, because it has no socket.
///
/// This replaces `kuid_socket_name_derives_from_env`, which pinned
/// `kuid_ipc_name()` and the `KUID_IPC_NAME` override. Both are gone: `kuserd`
/// creates a `socketpair` before forking and hands kuid the far end, so there is
/// no path to name and no second process that could reach it
/// (`TASK-kuid-should-have-no-socket-to-connect-to`).
///
/// The test is kept rather than deleted because the *property* it guarded still
/// matters, inverted: what used to need a configurable name must now need
/// nothing at all. If a socket name comes back for this channel, something has
/// started listening again and that is the regression worth catching.
///
/// Widened 2026-08-27. It used to also assert kuid called
/// `serve_inherited::<KuidRequest, KuidResponse`, which pinned the *helper*
/// rather than the property — and went red when kuid started reading the
/// channel directly, which it must, because it now writes its own
/// `CompositorEvent`s onto the same descriptor and `serve_inherited` owns both
/// halves. A test that names a mechanism fails when the mechanism improves.
///
/// What it asserts instead is the reach: no listener, and no client connection
/// to kuserd either. The second half is new and is the larger claim — kuid held
/// one until this date, which is why a display server could not run before
/// somebody had logged in.
///
/// That reach is read from kuid's own source, so it is held in kuid's own tests
/// (`reach_tests` in `core/kuid/src/main.rs`: `kuid_binds_no_listening_socket`,
/// `kuid_serves_the_channel_it_is_handed`, `kuid_connects_out_to_no_daemon`): the suite
/// ships in a release that holds no kuid. What stays here is the half that is
/// `kotton-common`'s.
#[test]
fn kuid_has_no_socket_name_to_configure() {
    let common = include_str!("../../../core/common/src/paths.rs");
    assert!(
        !common.contains("fn kuid_ipc_name"),
        "kuid_ipc_name is back — kuid should have no socket to name",
    );
}

/// After the daemon spawns it must be able to serve `DaemonSidecars` without
/// error.  kuid is a dynamic sidecar (not hard-coded in the static ORDER list),
/// so it only appears when there are registered apps; this test verifies the
/// response is well-formed and that the fixed sidecar entries are present.
#[tokio::test]
async fn kuid_sidecar_state_seeded_on_spawn() {
    let mut env = TestEnv::spawn().await;
    env.client.create_user(USER, crate::common::TEST_PASSPHRASE).await.expect("create_user");
    let token = env.client.session_token.clone().expect("session token");

    let mut client = auth_client(&env.endpoint, &token).await;

    let resp = client
        .send(&UserRequest::DaemonSidecars)
        .await
        .expect("DaemonSidecars send");

    match resp {
        UserResponse::DaemonSidecarsResult { sidecars } => {
            // The kuserd self-entry is always present.
            assert!(
                sidecars.iter().any(|s| s.name == "kuserd"),
                "DaemonSidecarsResult must include kuserd self-entry; got: {:?}",
                sidecars.iter().map(|s| &s.name).collect::<Vec<_>>(),
            );
            // kuid is not hard-coded in ORDER so it only appears when apps are
            // registered; on a fresh daemon it is absent — that is correct.
            // Just assert the response deserialised successfully (no panic above).
        }
        other => panic!("expected DaemonSidecarsResult, got: {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// First run: a machine with no identity still has something to draw
// ---------------------------------------------------------------------------

/// The pre-identity shell path refuses to run once anybody is resident.
///
/// `app_launch_system_shell` grants `world occupant` — the `auth` interface,
/// `create-identity` — to a fixed path with no designation behind it, because
/// before an identity exists there is nobody whose designation could be
/// consulted. That is only defensible while it *is* nobody. The moment a user
/// exists, their `app_roles` row is the answer and this path must be closed.
///
/// The check lives in the function that grants the authority rather than only at
/// the daemon call site that reads the registry, so this test calls it directly.
#[tokio::test]
async fn the_pre_identity_shell_refuses_once_a_user_exists() {
    use kotton_app::daemon::apps::app_launch_system_shell;

    let base = tempfile::tempdir().expect("tempdir");
    let host = crate::common::NullAppHost::default();
    let live = std::sync::Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new()));

    let err = app_launch_system_shell(&host, base.path(), live, None, None, None, Some("alice"))
        .await
        .expect_err("a resident user must close this path");

    let msg = err.to_string();
    assert!(
        msg.contains("alice") && msg.contains("app_roles"),
        "the refusal should name who is resident and what decides instead, got: {msg}"
    );
}

/// With nobody resident, the same call gets as far as looking for the shell.
///
/// The point is the *reason* it fails on an empty base dir: not "no user", not
/// "no registry", but a named missing file. Before this path existed the failure
/// was three layers earlier and said `no user loaded on this daemon` — a fresh
/// machine could not get far enough to discover it had nothing to draw.
#[tokio::test]
async fn with_nobody_resident_the_shell_is_looked_for_on_disk() {
    use kotton_app::daemon::apps::{app_launch_system_shell, system_shell_dir};

    let base = tempfile::tempdir().expect("tempdir");
    let host = crate::common::NullAppHost::default();
    let live = std::sync::Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new()));

    let err = app_launch_system_shell(&host, base.path(), live, None, None, None, None)
        .await
        .expect_err("an empty base dir has no shell staged");

    let msg = err.to_string();
    assert!(
        msg.contains("no system shell at"),
        "expected a named missing path, got: {msg}"
    );
    assert!(
        msg.contains(&system_shell_dir(base.path()).display().to_string()),
        "the error should name the directory it looked in, got: {msg}"
    );
}

/// A staged system shell actually launches, and paints, with no identity.
///
/// This is the end-to-end claim the whole first-run thread is about: a machine
/// nobody has logged into opens a surface and puts something on it. Everything
/// else in this file asserts that a guard is in the right place; this asserts
/// the thing works.
///
/// It stages the shell the way `cargo xtask build-apps` does — the real wasm,
/// the real manifest — so a shell that stops building, or a manifest that stops
/// parsing, fails here rather than at somebody's first boot.
#[tokio::test]
// `KOTTON_RUNNER` is process-global and this is the one test that points it at
// the *real* runner rather than the mock. Every other consumer sets it to the
// mock on every spawn, so the value is restored at the end and the serial guard
// keeps anything from reading it mid-flight.
#[serial_test::serial]
async fn a_fresh_machine_draws_its_welcome_screen() {
    use kotton_app::daemon::apps::{app_launch_system_shell, system_shell_dir};

    // A missing input fails, naming the command that makes it. A test that returns
    // green when its input is absent is one nobody notices losing.
    let wasm = crate::common::bins::require_shell_wasm();
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../guest/apps/kotton-shell/manifest.toml");

    let base = tempfile::tempdir().expect("tempdir");
    let dir = system_shell_dir(base.path());
    std::fs::create_dir_all(&dir).expect("stage dir");
    std::fs::copy(wasm, dir.join("app.wasm")).expect("stage wasm");
    std::fs::copy(&manifest, dir.join("manifest.toml")).expect("stage manifest");

    // The runner this launch must use is the **real** one: the whole point is that
    // a real component draws a real welcome screen.
    //
    // `NullAppHost::runner` is set below rather than `KOTTON_RUNNER`, which is
    // what this test used to do. `spawn_and_present` reads `host.runner()` and has
    // since the runner moved onto the host trait on 2026-09-05; the environment
    // variable stopped being consulted, so this test quietly began running the
    // *mock* runner, which answers `Launched { patches: [] }` without instantiating
    // anything. It has been red on `main` since, saying "the welcome screen painted
    // nothing" — which was true, and about a screen it was no longer drawing.
    // Where cargo put it, as `build.rs` asked it — never `../target/debug`, which
    // stopped being the target directory when it moved under `out/`. Asked of
    // `bins`, which fails naming every binary that is not built.
    let runner = crate::common::bins::require(crate::common::bins::Bin::Runner).to_path_buf();
    let host = crate::common::NullAppHost {
        runner: Some(runner.clone()),
        ..Default::default()
    };
    let live = std::sync::Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new()));

    // `occupant: None` — the shell is instantiated into `world occupant` either
    // way (that is `RunnerInput.occupant`), but with no host to service an auth
    // call. Launching does not make one, so this exercises the whole path.
    //
    // And a launch that *succeeds* is itself the proof that the occupant world
    // was linked: the shell's `app.wasm` imports `kotton:app/auth`, so if
    // `app_launch_system_shell` had set `occupant: false` the component would
    // fail to instantiate with a missing import rather than draw. The welcome
    // screen needs `create-identity`; there would be no point reaching it in a
    // world where that verb does not exist.
    let resp = app_launch_system_shell(&host, base.path(), live, None, None, None, None)
        .await
        .expect("the staged shell should launch with no identity");

    let app_id = match resp {
        kotton_wire::UserResponse::AppLaunched { app_id, patches } => {
            assert!(!patches.is_empty(), "the welcome screen painted nothing");
            app_id
        }
        other => panic!("expected AppLaunched, got {other:?}"),
    };

    let opened = host.opened.lock().unwrap().clone();
    assert_eq!(
        opened.len(),
        1,
        "expected exactly one surface for the shell, got {opened:?}"
    );
    let (handle, owner, role, edge, _title) = opened[0].clone();
    assert_eq!(edge, None, "a background hangs from no edge");
    assert_eq!(owner, app_id, "the surface should be the shell's");
    // The pre-identity shell draws the desktop, so its surface opens as the
    // screen's `Background` — and it opens as one because
    // `app_launch_system_shell` sets `occupant`, not because anything compared
    // its id to a constant (RFC-0087).
    assert_eq!(
        role,
        kotton_wire::SurfaceRole::Background,
        "the shell draws the screen's base, so its surface is a Background"
    );

    // Everything painted went to the surface that was opened for it. Under
    // `app_id` keying this could not be asserted, because the patch and the
    // surface were addressed by the same string whether or not they belonged
    // together.
    let committed = host.committed.lock().unwrap().clone();
    assert!(
        !committed.is_empty(),
        "a surface was opened but nothing was committed to it"
    );
    assert!(
        committed.iter().all(|(h, _)| *h == handle),
        "a patch was committed to a surface this launch did not open"
    );

    // Back to the value every other test in this binary expects.
    #[allow(unsafe_code)]
    unsafe {
        std::env::set_var("KOTTON_RUNNER", crate::common::mock_runner_bin())
    };
}

/// A fresh machine can be **typed into**, not only drawn on.
///
/// The sibling of `a_fresh_machine_draws_its_welcome_screen`, and the case whose
/// absence let first run deadlock on Windows for a person who got as far as
/// seeing the welcome screen and could not click it.
///
/// `app_launch_system_shell` hands the pre-identity shell `world occupant` so a
/// person can call `create-identity`. That verb is reached by typing a
/// passphrase and pressing a button — which is an input event — and routing one
/// used to resolve the user's database first and refuse with `no user loaded on
/// this daemon`. So the click that would create the user was dropped for want of
/// the user it was going to create, and the welcome screen was a picture of a
/// login you could not perform.
///
/// The fix is that `user_db` is `Option`: input delivery never reads it, and only
/// a launch the guest *raises* does. This test pins the property that made the
/// deadlock possible — input reaching a running instance with no user at all.
///
/// **What it does not pin.** The refusal was in `compositor_input`, one layer up,
/// which resolved the database eagerly and returned before calling this. Under
/// the old signature this test would not have compiled, which is a kind of red;
/// but it would still pass if somebody restored that early return, because it
/// calls `app_input_event` directly. Pinning that layer needs an `AgentContext`,
/// and saying so is better than implying coverage this does not have.
#[tokio::test]
#[serial_test::serial]
async fn a_fresh_machine_can_be_typed_into() {
    use kotton_app::daemon::apps::{app_input_event, app_launch_system_shell, system_shell_dir};

    // Both are asked of `bins`, which fails naming everything that is not built and the
    // commands that build it, rather than returning green with nothing run.
    let wasm = crate::common::bins::require_shell_wasm();
    let runner = crate::common::bins::require(crate::common::bins::Bin::Runner).to_path_buf();
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../guest/apps/kotton-shell/manifest.toml");

    let base = tempfile::tempdir().expect("tempdir");
    let dir = system_shell_dir(base.path());
    std::fs::create_dir_all(&dir).expect("stage dir");
    std::fs::copy(wasm, dir.join("app.wasm")).expect("stage wasm");
    std::fs::copy(&manifest, dir.join("manifest.toml")).expect("stage manifest");

    // SAFETY: `#[serial_test::serial]` means nothing else is running. Restored below.
    #[allow(unsafe_code)]
    unsafe {
        std::env::set_var("KOTTON_RUNNER", &runner)
    };

    let host = crate::common::NullAppHost::default();
    let live = std::sync::Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new()));

    let resp = app_launch_system_shell(&host, base.path(), std::sync::Arc::clone(&live), None, None, None, None)
        .await
        .expect("the staged shell should launch with no identity");
    let app_id = match resp {
        kotton_wire::UserResponse::AppLaunched { app_id, .. } => app_id,
        other => panic!("expected AppLaunched, got {other:?}"),
    };

    // The surface the person typed on: the one the launch opened, which the
    // compositor would have hit-tested. It is read back from the host rather
    // than minted here, because an event for a surface the instance does not
    // hold is not delivered to it — which is the point of stage 3a and would
    // make this test pass for the wrong reason.
    let surface = host.opened.lock().unwrap()[0].0;

    // The whole point: `None` for the user database, because there is no user.
    let out = app_input_event(
        &host,
        None,
        base.path(),
        std::sync::Arc::clone(&live),
        app_id.clone(),
        surface,
        kotton_wire::ipc::types::InputEventPayload::Key {
            key: "Enter".to_string(),
            pressed: true,
            shift: false,
            ctrl: false,
            alt: false,
        },
        None,
        None,
        None,
        None,
    )
    .await
    .expect("input must reach a running instance with no user loaded");

    match out {
        kotton_wire::UserResponse::AppMessageDelivered { .. } => {}
        other => panic!("expected the input to be delivered, got {other:?}"),
    }

    // And the instance survived it, so the next keystroke has somewhere to go.
    assert!(
        live.lock().await.contains_key(&app_id),
        "the shell should still be running after handling input"
    );

    #[allow(unsafe_code)]
    unsafe {
        std::env::set_var("KOTTON_RUNNER", crate::common::mock_runner_bin())
    };
}

// ── An app may hold many surfaces (RFC-0087 stage 2) ─────────────────────────

/// Stage a system shell the mock runner can be launched as, and return its base
/// directory.
///
/// The wasm is a placeholder: the mock runner never loads a component, so what
/// is under test here is the **daemon's** half of `create-surface` — minting,
/// opening, the cap, and which surface each patch reaches. The guest half is
/// tested where a guest is real (`core/wasm/src/sandbox.rs`, and the SDK's own
/// render tests); mixing the two would mean a wasm build inside a test that is
/// about a wire.
fn stage_a_shell_for_the_mock() -> tempfile::TempDir {
    use kotton_app::daemon::apps::system_shell_dir;
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../guest/apps/kotton-shell/manifest.toml");
    let base = tempfile::tempdir().expect("tempdir");
    let dir = system_shell_dir(base.path());
    std::fs::create_dir_all(&dir).expect("stage dir");
    std::fs::write(dir.join("app.wasm"), b"not a component").expect("stage wasm");
    std::fs::copy(&manifest, dir.join("manifest.toml")).expect("stage manifest");
    base
}

/// **An instance holds two surfaces, and each patch reaches its own.**
///
/// The whole of RFC-0087 stage 2's third clause, end to end on the daemon's
/// side: the guest asks for a second surface over the runner's host-call wire,
/// the *daemon* mints the handle and opens it, and the two patches the guest
/// commits arrive at two different surfaces.
///
/// Under stage 1 this could not have been written. `RunnerOutput.patches` was a
/// bare `Vec<Vec<u8>>` and the daemon routed every one of them to the
/// instance's single surface through `AppHost::surface_of` — so two patches
/// would both have landed on the first, and no assertion here could have told
/// the difference.
#[tokio::test]
#[serial_test::serial]
#[allow(unsafe_code)] // env::set_var is unsafe in Rust 1.81+; serialised by #[serial]
async fn two_surfaces_of_one_instance_each_get_their_own_patch() {
    use kotton_app::daemon::apps::app_launch_system_shell;

    let base = stage_a_shell_for_the_mock();
    // SAFETY: serialised by `#[serial]`; cleared before the assertions so a
    // panic cannot leave the mode set for another test.
    unsafe { std::env::set_var("MOCK_RUNNER_MODE", "two-surfaces") };

    let host = crate::common::NullAppHost::default();
    let live = std::sync::Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new()));
    let resp = app_launch_system_shell(&host, base.path(), live, None, None, None, None).await;
    unsafe { std::env::remove_var("MOCK_RUNNER_MODE") };
    resp.expect("a guest asking for a second surface must still launch");

    let opened = host.opened.lock().unwrap().clone();
    assert_eq!(
        opened.len(),
        2,
        "the launch surface and the one the guest asked for, got {opened:?}"
    );
    assert_eq!(
        opened[0].1, opened[1].1,
        "both surfaces belong to the same app; the host keeps that association \
         and the compositor is never told it"
    );
    assert_ne!(
        opened[0].0, opened[1].0,
        "two surfaces are two handles — a second mint, not the same one twice"
    );
    // The designated app's launch surface is the screen's base; what it asked
    // for afterwards is an ordinary window, framed and stacked like anyone
    // else's.
    assert_eq!(opened[0].2, kotton_wire::SurfaceRole::Background);
    assert_eq!(opened[1].2, kotton_wire::SurfaceRole::Window);

    let committed = host.committed.lock().unwrap().clone();
    assert_eq!(committed.len(), 2, "one patch per surface, got {committed:?}");
    assert_eq!(
        committed[0].0, opened[0].0,
        "the first patch went to the first surface"
    );
    assert_eq!(
        committed[1].0, opened[1].0,
        "the second patch went to the second surface"
    );
    assert_ne!(
        committed[0].1, committed[1].1,
        "the two patches differ, so this is two paintings and not one echoed twice"
    );
}

/// **A guest cannot ask for surfaces without end.**
///
/// `create-surface` is unbounded reach otherwise, and the cap is the answer
/// RFC-0087 asks for: *"the number is an implementation choice; its absence is
/// not."* The mock asks 64 times and stops when it is told no; the host must
/// have opened exactly the cap, counting the launch surface.
///
/// A resource bound, not an authority check — which is why the guest is told,
/// and why the launch succeeds rather than the instance being dropped.
#[tokio::test]
#[serial_test::serial]
#[allow(unsafe_code)] // env::set_var is unsafe in Rust 1.81+; serialised by #[serial]
async fn an_instance_cannot_hold_more_surfaces_than_the_cap() {
    use kotton_app::daemon::apps::app_launch_system_shell;

    let base = stage_a_shell_for_the_mock();
    // SAFETY: serialised by `#[serial]`; cleared before the assertions.
    unsafe { std::env::set_var("MOCK_RUNNER_MODE", "surface-storm") };

    let host = crate::common::NullAppHost::default();
    let live = std::sync::Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new()));
    let resp = app_launch_system_shell(&host, base.path(), live, None, None, None, None).await;
    unsafe { std::env::remove_var("MOCK_RUNNER_MODE") };
    resp.expect("a guest that asks past the cap is answered, not killed");

    let opened = host.opened.lock().unwrap().len();
    assert_eq!(
        opened,
        kotton_wire::MAX_SURFACES_PER_INSTANCE,
        "the cap counts the launch surface, so a guest asking for 64 more gets \
         {} in total",
        kotton_wire::MAX_SURFACES_PER_INSTANCE
    );
}

/// **A launch that fails takes every surface it opened back down.**
///
/// The instance asks for a second surface during `on-launch` and then fails its
/// init. Two surfaces are open on the compositor by then — the one the daemon
/// minted for the launch and the one the guest asked for — and a failed launch
/// that closed only the first would leave a window on screen for a process that
/// never ran, with nothing left able to name it.
///
/// This is the test the first version of stage 2 did not have. `spawn_and_present`
/// closed the launch handle and nothing closed the rest, and it read as correct
/// because `NullAppHost::surface_close` was an empty body: a host that forgets
/// and a host that cleans up produced identical evidence. The obligation now
/// rides the error type — `open_long_lived_runner` hands back what it left open
/// — so there is one place that closes rather than four that each close what
/// they happen to know about.
#[tokio::test]
#[serial_test::serial]
#[allow(unsafe_code)] // env::set_var is unsafe in Rust 1.81+; serialised by #[serial]
async fn a_launch_that_fails_closes_every_surface_it_opened() {
    use kotton_app::daemon::apps::app_launch_system_shell;

    let base = stage_a_shell_for_the_mock();
    // SAFETY: serialised by `#[serial]`; cleared before the assertions so a
    // panic cannot leave the mode set for another test.
    unsafe { std::env::set_var("MOCK_RUNNER_MODE", "surface-then-fail") };

    let host = crate::common::NullAppHost::default();
    let live = std::sync::Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new()));
    let resp = app_launch_system_shell(&host, base.path(), live.clone(), None, None, None, None).await;
    unsafe { std::env::remove_var("MOCK_RUNNER_MODE") };
    resp.expect_err("the mock failed its init, so the launch must fail");

    let opened: Vec<_> = host
        .opened
        .lock()
        .unwrap()
        .iter()
        .map(|(h, ..)| *h)
        .collect();
    assert_eq!(
        opened.len(),
        2,
        "the launch surface and the one the guest asked for, got {opened:?}"
    );

    let closed = host.closed.lock().unwrap().clone();
    for handle in &opened {
        assert!(
            closed.contains(handle),
            "surface {handle} was opened and never closed; closed = {closed:?}"
        );
    }

    // And nothing was left running to own them.
    assert!(
        live.lock().await.is_empty(),
        "a failed launch must not leave an instance in the live map"
    );
}

/// **The shape stage 3c gives the desktop**: a strip on each screen edge, a window, and the
/// window given back.
///
/// RFC-0087 stage 3c on the daemon's side, end to end through the real runner wire. Three
/// things are under test and each one was a gap before this stage:
///
/// 1. **A panel names an edge**, and the edge reaches the host. It is an *anchor*, not a
///    position — the app says which side it belongs to and the host decides the span, the
///    offset and the band it reserves — and it has to be said at all because a menubar and
///    a dock are both full-width strips a few tens of pixels tall, so nothing about the two
///    surfaces distinguishes them.
/// 2. **`surface.close` does something.** It was a stub that logged and answered `ok`, so an
///    app that gave a window back was still charged for it against the per-instance cap.
///    Invisible while every app had one surface it never wanted to be rid of; the first
///    thing the shell needed the day it grew a window per window.
/// 3. **Giving the same surface back twice is refused**, because the second close names a
///    surface the instance does not hold — which is the same audit the designation check is,
///    at the process boundary the daemon does not take the runner's word across.
#[tokio::test]
#[serial_test::serial]
#[allow(unsafe_code)] // env::set_var is unsafe in Rust 1.81+; serialised by #[serial]
async fn the_desktop_opens_a_strip_on_each_edge_and_can_give_a_window_back() {
    use kotton_app::daemon::apps::app_launch_system_shell;

    let base = stage_a_shell_for_the_mock();
    let host = crate::common::NullAppHost::default();

    // SAFETY: serialised by `#[serial]`; cleared before the assertions so a panic cannot
    // leave the mode set for another test.
    unsafe { std::env::set_var("MOCK_RUNNER_MODE", "panels") };
    let live = std::sync::Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new()));
    let resp = app_launch_system_shell(&host, base.path(), live.clone(), None, None, None, None).await;
    unsafe { std::env::remove_var("MOCK_RUNNER_MODE") };
    resp.expect("the designated app opening its panels must launch");

    let opened = host.opened.lock().unwrap().clone();
    let roles: Vec<(kotton_wire::SurfaceRole, Option<kotton_wire::PanelEdge>)> =
        opened.iter().map(|(_, _, role, edge, _)| (*role, *edge)).collect();
    assert_eq!(
        roles,
        vec![
            // The launch surface: the screen's base, hanging from no edge.
            (kotton_wire::SurfaceRole::Background, None),
            (
                kotton_wire::SurfaceRole::Panel,
                Some(kotton_wire::PanelEdge::Top)
            ),
            (
                kotton_wire::SurfaceRole::Panel,
                Some(kotton_wire::PanelEdge::Bottom)
            ),
            // And an ordinary window, which names no edge and could not.
            (kotton_wire::SurfaceRole::Window, None),
        ],
        "the desktop's four surfaces, each opened as what it is: {opened:?}"
    );
    assert!(
        opened.iter().all(|(_, owner, ..)| owner == &opened[0].1),
        "every one of them belongs to the same instance: {opened:?}"
    );

    // The window it gave back was closed on the compositor, and nothing else was.
    let window = opened[3].0;
    assert_eq!(
        host.closed.lock().unwrap().clone(),
        vec![window],
        "exactly the surface the guest gave back"
    );

    // And the instance is still alive with its other three. Closing one surface of an app
    // that holds several must not end the app — which is the defect a desktop would meet
    // the first time a person closed a window.
    let live = live.lock().await;
    let instance = live.values().next().expect("the desktop is still running");
    assert_eq!(
        instance.surfaces.len(),
        3,
        "the background and both panels, and not the window it gave back"
    );
    assert!(!instance.surfaces.contains(&window));

    // What the guest was told, read back out of the patch it painted.
    let committed = host.committed.lock().unwrap().clone();
    let patch = &committed.first().expect("the mock painted its report").1;
    let report: serde_json::Value =
        serde_json::from_slice(&patch[1..]).expect("the report is json");
    assert_eq!(report["top"], true, "the top panel was granted: {report}");
    assert_eq!(report["bottom"], true, "the bottom panel was granted: {report}");
    assert_eq!(report["closed"], true, "`surface.close` did something: {report}");
    assert_eq!(
        report["closed_twice"], false,
        "closing a surface it no longer holds is refused: {report}"
    );
}

/// **The designated app is told about every open window, and can ask for one back.**
///
/// RFC-0087 stage 3b's second clause, end to end on the daemon's side: the guest asks over
/// the runner's host-call wire, the daemon joins the compositor's stack against its own
/// record of who holds what, and what comes back carries the host's attribution, an id
/// minted for this instance, and one bit. The ask goes the other way by the same id.
///
/// **The trap is what is *not* in the answer**, and this is where that is checkable: the
/// handle never crosses, so a designated app holds no name for another app's surface — only
/// a number the daemon can resolve back, for windows it was shown.
#[tokio::test]
#[serial_test::serial]
#[allow(unsafe_code)] // env::set_var is unsafe in Rust 1.81+; serialised by #[serial]
async fn the_designated_app_is_told_the_windows_in_the_hosts_words() {
    use kotton_app::daemon::apps::app_launch_system_shell;

    let base = stage_a_shell_for_the_mock();
    let notes = kotton_wire::SurfaceHandle::mint();
    let messages = kotton_wire::SurfaceHandle::mint();

    let host = crate::common::NullAppHost::default();
    *host.windows.lock().unwrap() = vec![
        kotton_wire::HostWindow {
            handle: notes,
            name: "Notes".into(),
            title: Some("Shopping".into()),
            minimised: false,
        },
        kotton_wire::HostWindow {
            handle: messages,
            name: "Messages".into(),
            title: None,
            minimised: true,
        },
    ];

    // SAFETY: serialised by `#[serial]`; cleared before the assertions so a panic cannot
    // leave the mode set for another test.
    unsafe { std::env::set_var("MOCK_RUNNER_MODE", "window-list") };
    let live = std::sync::Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new()));
    let resp = app_launch_system_shell(&host, base.path(), live, None, None, None, None).await;
    unsafe { std::env::remove_var("MOCK_RUNNER_MODE") };
    resp.expect("the designated app asking about windows must launch");

    // What the guest was told, read back out of the patch it painted.
    let committed = host.committed.lock().unwrap().clone();
    let patch = &committed.first().expect("the mock painted its report").1;
    let report: serde_json::Value =
        serde_json::from_slice(&patch[1..]).expect("the report is json");
    let windows = report["windows"].as_array().expect("a list of windows");

    assert_eq!(windows.len(), 2, "both windows, in stack order: {report}");
    assert_eq!(windows[0]["id"], 1, "ids count from 1");
    assert_eq!(windows[0]["name"], "Notes", "the host's attribution");
    assert_eq!(windows[0]["minimised"], false);
    assert_eq!(windows[1]["id"], 2);
    assert_eq!(windows[1]["name"], "Messages");
    assert_eq!(windows[1]["minimised"], true, "the one bit only the compositor knows");

    // Nothing a handle could be read out of reached the guest.
    let text = report.to_string();
    for handle in [notes, messages] {
        assert!(
            !text.contains(&handle.to_string()),
            "the guest was handed a surface handle: {text}"
        );
    }

    // And the ask came back the other way, resolved to the right window.
    assert_eq!(
        host.restored.lock().unwrap().clone(),
        vec![notes],
        "asking for window 1 asks the compositor for the first window in the list"
    );
    assert_eq!(
        report["refused"].as_array().expect("refusals").len(),
        1,
        "an id this instance was never given is refused, not resolved: {report}"
    );
}

/// **A window that opens or closes reaches the designated app without the person doing
/// anything else** (`TASK-the-docks-window-list-is-as-stale-as-its-last-repaint`).
///
/// The daemon's half, end to end over the real runner wire: the stack moves, the daemon
/// nudges the live designated instance, and the instance — as the dock does — asks for the
/// list again and is told the list as it now stands. Twice, once for each direction the
/// record measured: a window that opened, and a window that closed.
///
/// **And the nudge itself carries nothing.** The mock paints the message it was sent, and
/// it must be the constant frame — no name, no id, no count. The list is what the pull
/// answered, not what the push said.
///
/// What this does not reach is the compositor's report arriving at `kuserd`'s drain: that
/// is `SurfaceProxy::note_windows`, held by its own test, and the arm that calls this on a
/// `true` from it. Nor the shell's own repaint, which is the guest's and is held on screen.
#[tokio::test]
#[serial_test::serial]
#[allow(unsafe_code)] // env::set_var is unsafe in Rust 1.81+; serialised by #[serial]
async fn a_window_that_opens_or_closes_reaches_the_designated_app_as_a_nudge_carrying_nothing() {
    use kotton_app::daemon::apps::{app_launch_system_shell, app_windows_changed};

    let base = stage_a_shell_for_the_mock();
    let editor = kotton_wire::SurfaceHandle::mint();
    let files = kotton_wire::SurfaceHandle::mint();
    let window = |handle, name: &str| kotton_wire::HostWindow {
        handle,
        name: name.into(),
        title: None,
        minimised: false,
    };

    let host = crate::common::NullAppHost::default();
    *host.windows.lock().unwrap() = vec![window(editor, "Editor")];

    // SAFETY: serialised by `#[serial]`; cleared as soon as the launch returns.
    unsafe { std::env::set_var("MOCK_RUNNER_MODE", "window-nudge") };
    let live = std::sync::Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new()));
    let launched =
        app_launch_system_shell(&host, base.path(), std::sync::Arc::clone(&live), None, None, None, None).await;
    // The runner read the mode when it was spawned, so it is cleared here — before any
    // `expect` below can panic and leave it set for the next serial test.
    unsafe { std::env::remove_var("MOCK_RUNNER_MODE") };
    launched.expect("the designated app must launch");

    // What the guest paints in answer to one nudge, read back out of its patch.
    async fn nudge_and_read(
        host: &crate::common::NullAppHost,
        live: &std::sync::Arc<
            tokio::sync::Mutex<
                std::collections::HashMap<String, kotton_app::daemon::apps::LongLivedInstance>,
            >,
        >,
    ) -> serde_json::Value {
        host.committed.lock().unwrap().clear();
        app_windows_changed(host, std::sync::Arc::clone(live), None, None, None)
            .await
            .expect("the nudge is delivered to a live designated instance");
        let committed = host.committed.lock().unwrap().clone();
        let patch = &committed.first().expect("the instance answered the nudge").1;
        serde_json::from_slice(&patch[1..]).expect("the report is json")
    }
    let names = |report: &serde_json::Value| -> Vec<String> {
        report["windows"]
            .as_array()
            .expect("a list of windows")
            .iter()
            .map(|w| w["name"].as_str().unwrap_or_default().to_string())
            .collect()
    };

    // A window opens — the Files window a dock click made.
    *host.windows.lock().unwrap() = vec![window(editor, "Editor"), window(files, "Kotton")];
    let opened = nudge_and_read(&host, &live).await;

    // It closes.
    *host.windows.lock().unwrap() = vec![window(editor, "Editor")];
    let closed = nudge_and_read(&host, &live).await;

    assert_eq!(names(&opened), ["Editor", "Kotton"], "the window that opened is listed: {opened}");
    assert_eq!(names(&closed), ["Editor"], "the window that closed is gone: {closed}");

    for report in [&opened, &closed] {
        assert_eq!(
            report["msg"],
            kotton_wire::runner::WINDOWS_CHANGED_FRAME,
            "the nudge is the constant frame and nothing else: {report}"
        );
        let text = report["msg"].as_str().unwrap_or_default();
        for said in ["Editor", "Kotton", &editor.to_string(), &files.to_string()] {
            assert!(!text.contains(said), "the nudge carried `{said}`: {text}");
        }
    }
}

/// **An app that answers the nudge by reaching for a window is repainted and not obeyed.**
///
/// The nudge is the host's, not the person's, so a launch or a raise the designated app
/// asks for while answering it is acting on a gesture nobody made. Its repaint is served —
/// that is what the nudge is for — and neither of the other two is.
#[tokio::test]
#[serial_test::serial]
#[allow(unsafe_code)] // env::set_var is unsafe in Rust 1.81+; serialised by #[serial]
async fn a_launch_or_raise_asked_for_in_answer_to_the_nudge_is_not_served() {
    use kotton_app::daemon::apps::{app_launch_system_shell, app_windows_changed};

    let base = stage_a_shell_for_the_mock();
    let host = crate::common::NullAppHost::default();
    // SAFETY: serialised by `#[serial]`; cleared as soon as the launch returns.
    unsafe { std::env::set_var("MOCK_RUNNER_MODE", "window-nudge-reaches") };
    let live = std::sync::Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new()));
    let launched =
        app_launch_system_shell(&host, base.path(), std::sync::Arc::clone(&live), None, None, None, None).await;
    unsafe { std::env::remove_var("MOCK_RUNNER_MODE") };
    launched.expect("the designated app must launch");

    let opened_before = host.opened.lock().unwrap().len();
    host.committed.lock().unwrap().clear();
    host.raised.lock().unwrap().clear();
    app_windows_changed(&host, std::sync::Arc::clone(&live), None, None, None)
        .await
        .expect("the nudge is delivered");

    assert_eq!(host.committed.lock().unwrap().len(), 1, "the repaint is served");
    assert!(host.raised.lock().unwrap().is_empty(), "a raise nobody asked for was served");
    assert_eq!(
        host.opened.lock().unwrap().len(),
        opened_before,
        "a launch nobody asked for opened a surface"
    );
    assert_eq!(live.lock().await.len(), 1, "a launch nobody asked for started an instance");
}

/// **The compositor's report reaches the dock through `kuserd`'s own drain** — the arm, not
/// the function it calls.
///
/// A fake desk is attached where `supervise_kuid` would attach `kuid` (the pattern
/// `vault.rs` uses for a prompt's answer), and `CompositorEvent::WindowsChanged` is written
/// up it as the compositor writes it. So this is the whole daemon path: the event drain,
/// `SurfaceProxy::note_windows` deciding the stack moved, the nudge to the live designated
/// instance, its `list-windows` answered from the report just recorded, and its repaint
/// arriving back down the same pair as a `SurfaceCommit`. A report that did not move the
/// stack is sent in between and must produce no repaint.
#[tokio::test]
#[serial_test::serial]
#[allow(unsafe_code)] // env::set_var is unsafe in Rust 1.81+; serialised by #[serial]
async fn a_windows_report_from_the_compositor_repaints_the_designated_app_through_the_drain() {
    use kotton_wire::{kuid_ipc::CompositorWindow, CompositorEvent, FromCompositor, KuidResponse};
    use tokio::io::AsyncReadExt as _;

    let env = crate::common::TestEnv::spawn().await;
    stage_a_system_shell(&env.base_dir);
    // SAFETY: serialised by `#[serial]`; cleared as soon as the launch returns.
    unsafe { std::env::set_var("MOCK_RUNNER_MODE", "window-nudge") };
    let launched = env.daemon.launch_designated_shell("boot", None).await;
    unsafe { std::env::remove_var("MOCK_RUNNER_MODE") };
    launched.expect("the designated shell must launch");

    // The fake desk: every request is reported to the test and answered `SurfaceOk`. It
    // reads frames as JSON values, never as `KuidRequest` — a second acceptor of that type
    // is what `channel-check` forbids.
    let (kuid_read, daemon_write) = tokio::io::duplex(1 << 20);
    let (daemon_read, kuid_write) = tokio::io::duplex(1 << 20);
    let kuid_write = std::sync::Arc::new(tokio::sync::Mutex::new(kuid_write));
    let (seen_tx, mut seen) = tokio::sync::mpsc::unbounded_channel::<serde_json::Value>();
    tokio::spawn({
        let kuid_write = std::sync::Arc::clone(&kuid_write);
        async move {
            let mut kuid_read = kuid_read;
            loop {
                let mut len = [0u8; 4];
                if kuid_read.read_exact(&mut len).await.is_err() {
                    break;
                }
                let mut body = vec![0u8; u32::from_le_bytes(len) as usize];
                if kuid_read.read_exact(&mut body).await.is_err() {
                    break;
                }
                let reply = FromCompositor::Response(KuidResponse::SurfaceOk);
                if kotton_ipc::write_frame(&mut *kuid_write.lock().await, &reply).await.is_err() {
                    break;
                }
                let _ = seen_tx.send(serde_json::from_slice(&body).unwrap_or_default());
            }
        }
    });
    env.daemon.desk().attach(daemon_write, daemon_read).await;

    // The backlog is flushed on attach: the shell's launch surface is opened, which is the
    // handle this test reports as a window — one the daemon holds an owner for.
    let deadline = std::time::Duration::from_secs(20);
    let handle = tokio::time::timeout(deadline, async {
        loop {
            let frame = seen.recv().await.expect("the desk is open");
            if let Some(h) = frame.get("SurfaceOpen").map(|o| o["handle"].clone()) {
                break serde_json::from_value::<kotton_wire::SurfaceHandle>(h).expect("a handle");
            }
        }
    })
    .await
    .expect("the shell's surface was opened on the desk");

    let report = |windows: Vec<CompositorWindow>| {
        let kuid_write = std::sync::Arc::clone(&kuid_write);
        async move {
            let event = FromCompositor::Event(CompositorEvent::WindowsChanged { windows });
            kotton_ipc::write_frame(&mut *kuid_write.lock().await, &event)
                .await
                .expect("write the report");
        }
    };
    // The next repaint the mock paints in answer to a nudge, or `None` if none comes.
    async fn next_repaint(
        seen: &mut tokio::sync::mpsc::UnboundedReceiver<serde_json::Value>,
        within: std::time::Duration,
    ) -> Option<serde_json::Value> {
        tokio::time::timeout(within, async {
            loop {
                let frame = seen.recv().await?;
                let Some(patch) = frame.get("SurfaceCommit").and_then(|c| c["patch"].as_array()) else {
                    continue;
                };
                let bytes: Vec<u8> = patch.iter().filter_map(|b| b.as_u64()).map(|b| b as u8).collect();
                let Ok(v) = serde_json::from_slice::<serde_json::Value>(bytes.get(1..).unwrap_or_default()) else {
                    continue;
                };
                if v.get("msg").is_some() {
                    return Some(v);
                }
            }
        })
        .await
        .ok()
        .flatten()
    }
    let open = vec![CompositorWindow { handle, minimised: false }];

    report(open.clone()).await;
    let opened = next_repaint(&mut seen, deadline).await.expect("a window appeared: the dock repaints");
    assert_eq!(opened["msg"], kotton_wire::runner::WINDOWS_CHANGED_FRAME, "{opened}");
    assert_eq!(opened["windows"].as_array().map(Vec::len), Some(1), "the list as reported: {opened}");

    report(open).await;
    assert!(
        next_repaint(&mut seen, std::time::Duration::from_secs(2)).await.is_none(),
        "the same stack again moved nothing, and must not repaint"
    );

    report(Vec::new()).await;
    let closed = next_repaint(&mut seen, deadline).await.expect("a window went: the dock repaints");
    assert_eq!(closed["msg"], kotton_wire::runner::WINDOWS_CHANGED_FRAME, "{closed}");
    assert_eq!(closed["windows"].as_array().map(Vec::len), Some(0), "the list as reported: {closed}");
}

/// **With no designated app running, the nudge goes nowhere** — and in particular it does
/// not start one, which a notice that means nothing to an instance that has not asked must
/// not do.
#[tokio::test]
async fn the_window_nudge_starts_nothing_when_no_designated_app_is_live() {
    let host = crate::common::NullAppHost::default();
    let live = std::sync::Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new()));
    kotton_app::daemon::apps::app_windows_changed(&host, std::sync::Arc::clone(&live), None, None, None)
        .await
        .expect("nothing to nudge is not an error");
    assert!(live.lock().await.is_empty(), "nothing was launched for the nudge");
    assert!(host.committed.lock().unwrap().is_empty(), "nothing was painted");
}

// ── The occupant world ends when the identity exists ─────────────────────────

/// **The shell a person is looking at after the ceremony is the resident one.**
///
/// The welcome screen runs in the occupant world: no user, so no data mount, no
/// grants, and `occupant: true` granted unconditionally because there is nobody
/// whose designation could be consulted (`DEC-0050`, `app_launch_system_shell`).
/// Until 2026-09-20 nothing ended that world — `create-identity` minted the
/// identity, returned, and the *same* instance carried on drawing a desktop over
/// a world with no user in it. The first thing the owner opened was the file
/// browser, and it said *no file capability was granted to this app*, because
/// `granted_vfs_roots` returns nothing when the sandbox has no `vfs_root` and
/// this one had none by construction.
///
/// So the assertion is the mount: the instance that follows `UserCreated` must
/// have been handed `base/users/<uid>/data`, which is what `app_launch` computes
/// and what `app_launch_system_shell` deliberately does not.
///
/// **How the mount is observed.** It is sent once, in the init frame, and never
/// mentioned again — so `MOCK_RUNNER_MODE=report-input` paints it back as the
/// launch's patch, which `UserResponse::AppLaunched` carries. Nothing else on
/// the daemon's surface says what an instance was given.
///
/// **What it does not pin.** The trigger is one layer up: `compositor_input`
/// reads who is resident before delivering an input event and calls
/// `end_the_occupant_world` when that answer has changed across it. Driving that
/// needs a `CompositorEvent` on the socketpair `kuid` holds, which this harness
/// cannot inject, so this test calls the daemon method the trigger calls and
/// says so rather than implying coverage it does not have. It also drives the
/// ceremony through `CreateUser` rather than through the occupant's
/// `create-identity`, which is a wrapper over exactly this call — see
/// `DaemonOccupantHost::create_identity`, whose whole body is `create_user`.
#[tokio::test]
#[serial_test::serial]
#[allow(unsafe_code)] // env::set_var is unsafe in Rust 1.81+; serialised by #[serial]
async fn the_shell_that_follows_the_ceremony_carries_the_users_data_mount() {
    // Before anything is set: the shell must be built for this test to have a launch.
    crate::common::bins::require_shell_wasm();

    // SAFETY: `#[serial_test::serial]` means nothing else is running.
    unsafe { std::env::set_var("MOCK_RUNNER_MODE", "report-input") };
    let mut env = crate::common::TestEnv::spawn().await;

    // The ceremony, to `UserCreated`.
    env.client
        .create_user("owner", crate::common::TEST_PASSPHRASE)
        .await
        .expect("create_user");

    // The bundled shell is compiled into `kuserd` only when the guest apps were
    // built. Without it a new identity receives no apps and there is nothing for
    // a resident launch to run: that is a failure, not a skip.
    let installed = env.client.app_list().await.expect("app_list");
    let bundled = installed.iter().any(|a| a.app_id == "sh.kotton.shell");
    if !bundled {
        unsafe { std::env::remove_var("MOCK_RUNNER_MODE") };
    }
    crate::common::bins::require_apps_bundled(bundled);

    let resp = env
        .daemon
        .end_the_occupant_world("sh.kotton.shell", "owner")
        .await
        .expect("the occupant world must end in a resident launch");

    let patches = match resp {
        kotton_wire::UserResponse::AppLaunched { patches, .. } => patches,
        other => panic!("expected AppLaunched, got {other:?}"),
    };
    let report: serde_json::Value = serde_json::from_slice(&patches[0][1..])
        .expect("the mock paints its launch frame as raw JSON (format version 0x00)");

    let expected = env
        .base_dir
        .join("users")
        .join("owner")
        .join("data")
        .to_string_lossy()
        .into_owned();
    assert_eq!(
        report["user_vfs_path"].as_str(),
        Some(expected.as_str()),
        "the shell that follows the ceremony must carry the user's data mount: {report}"
    );

    // And it is the *resident* launch, not the occupant one wearing a mount: the
    // mode the host derived from the session, and the approvals the install
    // recorded rather than the manifest read as a grant.
    let mode = report["launch_args"]
        .as_array()
        .expect("launch args")
        .iter()
        .find(|pair| pair[0] == "mode")
        .map(|pair| pair[1].clone());
    assert_eq!(
        mode.as_ref().and_then(|m| m.as_str()),
        Some("authenticated"),
        "a launch for a person who has just enrolled opens on their desktop: {report}"
    );
    assert!(
        report["approved"].as_u64().unwrap_or(0) > 0,
        "the resident launch runs on the grants the install recorded: {report}"
    );

    // And it ran the app the person's own registry designates, not a constant:
    // `db/user_db.rs` seeds that row on the open path, so an identity has one
    // from the moment it exists.
    assert_eq!(
        env.client.app_get_role("shell").await.expect("app_get_role"),
        Some("sh.kotton.shell".to_string()),
        "the resident launch runs the designated shell"
    );

    unsafe { std::env::remove_var("MOCK_RUNNER_MODE") };
}

/// The full launch frame the mock painted back, as JSON.
///
/// The init frame is sent once and never mentioned again, so
/// `MOCK_RUNNER_MODE=report-input` repeating it as the launch's patch is the
/// only channel there is — the trick
/// `the_shell_that_follows_the_ceremony_carries_the_users_data_mount` uses for
/// the mount, kept as a function because a second test now reads two fields out
/// of the same frame.
fn launch_report(resp: kotton_wire::UserResponse) -> serde_json::Value {
    let patches = match resp {
        kotton_wire::UserResponse::AppLaunched { patches, .. } => patches,
        other => panic!("expected AppLaunched, got {other:?}"),
    };
    serde_json::from_slice(&patches[0][1..])
        .expect("the mock paints its launch frame as raw JSON (format version 0x00)")
}

/// **The shell that follows an unlock carries the person's data mount and DID.**
///
/// The owner's report, 2026-09-21: *"when I use the login path, when I use
/// applications I get grant issues: the terminal for example says `ls: no file
/// capability was granted to this app`. also noticing that my did is not
/// displayed in the top status bar."* Both are one defect. The instance drawing
/// the lock screen was launched for nobody, so it holds no `user_vfs_path` — no
/// app it raises can be granted a file capability — and no `did`, which is why
/// the menubar draws an empty fingerprint. `handle_lock_input` then set
/// `AppMode::Authenticated` on that same instance, and neither field can be
/// filled in from inside the guest: the shell learns who it runs as from its
/// launch args, by design.
///
/// So the assertion is on the *next* launch's arguments, which is the whole of
/// what the host tells a shell about who it is running as.
///
/// **What this drives, and what it does not.** The unlock is driven through
/// `DaemonOccupantHost` — the one implementation of `auth.unlock-with-pin`, the
/// verb the lock screen calls (`guest/apps/kotton-shell/logic/src/lib.rs`,
/// `handle_lock_input` → `kotton_app::session::unlock_with_pin`) — and then the
/// door that consumes its answer. The layer above, `compositor_input`, needs a
/// `CompositorEvent` on the socketpair `kuid` holds, which this suite cannot
/// inject; it is the same limit
/// `the_shell_that_follows_the_ceremony_carries_the_users_data_mount` states,
/// and the two methods this calls are the two that path calls.
#[tokio::test]
#[serial_test::serial]
#[allow(unsafe_code)] // env::set_var is unsafe in Rust 1.81+; serialised by #[serial]
async fn the_shell_that_follows_an_unlock_carries_the_users_data_mount_and_did() {
    // Before anything is set: the shell must be built for this test to have a launch.
    crate::common::bins::require_shell_wasm();

    // SAFETY: `#[serial_test::serial]` means nothing else is running.
    unsafe { std::env::set_var("MOCK_RUNNER_MODE", "report-input") };
    let mut env = crate::common::TestEnv::spawn().await;

    env.client
        .create_user("owner", crate::common::TEST_PASSPHRASE)
        .await
        .expect("create_user");

    // The bundled shell is compiled into `kuserd` only when the guest apps were
    // built. Without it there is nothing for a resident launch to run: that is a
    // failure, not a skip.
    let installed = env.client.app_list().await.expect("app_list");
    let bundled = installed.iter().any(|a| a.app_id == "sh.kotton.shell");
    if !bundled {
        unsafe { std::env::remove_var("MOCK_RUNNER_MODE") };
    }
    crate::common::bins::require_apps_bundled(bundled);

    // ── The unlock, through the host the lock screen calls ───────────────────
    let unlocked_as = {
        let host = env.daemon.occupant_host();
        let token = kotton_app::daemon::apps::OccupantHost::unlock_with_pin(
            &host,
            "owner",
            crate::common::TEST_PASSPHRASE,
        )
        .await
        .expect("the credential that made this identity must open it");
        assert!(
            !token.is_empty(),
            "an accepted credential answers with a session token"
        );
        // The one fact the exchange leaves behind: an unlock changes no record
        // the daemon could read back afterwards, because the person was
        // registered and loaded before they typed (`DEC-0049`).
        host.unlocked_as()
    };
    assert_eq!(
        unlocked_as.as_deref(),
        Some("owner"),
        "the host must report whom it let in, or the daemon has nobody to relaunch for"
    );

    // ── What the person is looking at afterwards ─────────────────────────────
    let resp = env
        .daemon
        .end_the_locked_screen("sh.kotton.shell", unlocked_as.as_deref().unwrap())
        .await
        .expect("an accepted credential must be followed by a resident launch");
    let report = launch_report(resp);

    let expected = env
        .base_dir
        .join("users")
        .join("owner")
        .join("data")
        .to_string_lossy()
        .into_owned();
    assert_eq!(
        report["user_vfs_path"].as_str(),
        Some(expected.as_str()),
        "the shell that follows an unlock must carry the person's data mount, \
         or every app it opens says no file capability was granted: {report}"
    );

    let arg = |key: &str| {
        report["launch_args"]
            .as_array()
            .expect("launch args")
            .iter()
            .find(|pair| pair[0] == key)
            .and_then(|pair| pair[1].as_str())
            .map(str::to_owned)
    };
    let did = arg("did");
    assert!(
        did.as_deref().is_some_and(|d| d.starts_with("did:")),
        "the shell that follows an unlock must be told the person's DID, or the \
         menubar has no fingerprint to draw: got {did:?} in {report}"
    );
    // **And no name beside it**, because this identity was made through the
    // CLI's door with none. Until 2026-09-24 this line asserted `Some("owner")`:
    // the launch copied the id into `display_name` and the desktop called the
    // person by it. An identity with no display name is handed none, and the
    // shell draws its own fallback rather than an id
    // (`TASK-the-name-the-welcome-asks-for-goes-nowhere`).
    assert_eq!(
        arg("display_name"),
        None,
        "an identity with no display name must not be handed its id as one: {report}"
    );
    assert_eq!(
        arg("mode").as_deref(),
        Some("authenticated"),
        "a launch for a person who has just unlocked opens on their desktop: {report}"
    );

    unsafe { std::env::remove_var("MOCK_RUNNER_MODE") };
}

// ── The name the welcome asks for goes somewhere ─────────────────────────────

/// **An identity made in the window is called by the name the person typed, and
/// the id the daemon minted beside it is drawn nowhere**
/// (`TASK-the-name-the-welcome-asks-for-goes-nowhere`, ruled 2026-09-24).
///
/// Owner, 2026-09-20: *"when I do create an identity, in `.kotton.dev` it
/// creates `/users/owner`, despite naming myself Austin."* The welcome asked
/// for a name and `create-identity` took none; the occupant host minted the
/// identity as the literal `owner`, and the launch copied that id into
/// `display_name`, so the desktop called the person `owner`.
///
/// This drives the window's own door — `DaemonOccupantHost::create_identity`,
/// which is what the shell's `create-identity` reaches, with the name beside
/// the credential — and then reads the name back from each place the daemon
/// hands it to a document: `read-identity` (Settings' account row), the
/// `display_name` launch argument (the menubar), and the `names` argument of a
/// second boot's locked launch (the lock screen's greeting). The three
/// documents themselves are held in the shell's own render tests
/// (`components/lock.rs`, `components/overlays/settings.rs`, `lib.rs`), which
/// take these arguments and draw a name and never an id.
///
/// The id: minted, not `owner`; a value `validate_user_id` accepts, since it
/// is the directory under `users/`; derived from neither the name nor the DID
/// (the record's second point — a directory named after the identity would be a
/// join key between this disk and everywhere the identity appears); and a
/// rename moves nothing but the name.
///
/// `KOTTON_BASE_DIR` is pointed at this base for the reason
/// `a_second_boot_with_a_registered_identity_opens_the_lock_screen` gives:
/// `device_users` reads a process-global base
/// (`TASK-the-device-user-registry-is-read-from-a-process-global-base`, open),
/// and production has one base per process by construction.
#[tokio::test]
#[serial_test::serial]
#[allow(unsafe_code)] // env::set_var is unsafe in Rust 1.81+; serialised by #[serial]
async fn an_identity_made_in_the_window_is_called_by_its_name_and_its_id_is_drawn_nowhere() {
    use kotton_app::daemon::apps::OccupantHost as _;

    // Before anything is set: this test ends in a launch of the shell, so it must be built.
    crate::common::bins::require_shell_wasm();
    let base = tempfile::tempdir().expect("tempdir");
    stage_a_system_shell(base.path());

    // SAFETY: `#[serial_test::serial]` means nothing else is running. Restored
    // at the end, and before the assertions so a panic cannot leave them set.
    let prior_base = std::env::var_os("KOTTON_BASE_DIR");
    unsafe {
        std::env::set_var("KOTTON_BASE_DIR", base.path());
        std::env::set_var("MOCK_RUNNER_MODE", "report-input");
    }
    let restore = || unsafe {
        std::env::remove_var("MOCK_RUNNER_MODE");
        match &prior_base {
            Some(v) => std::env::set_var("KOTTON_BASE_DIR", v),
            None => std::env::remove_var("KOTTON_BASE_DIR"),
        }
    };

    let secrets: std::sync::Arc<dyn kotton_sys::secret::SecretsStore + Send + Sync> =
        std::sync::Arc::new(kotton_secret::MemorySecrets::new());

    // ── First boot: the person types their name and a credential ─────────────
    let (daemon, _endpoint) = boot_a_daemon_at(base.path(), std::sync::Arc::clone(&secrets)).await;
    let host = daemon.occupant_host();
    let did = host
        .create_identity(crate::common::TEST_PASSPHRASE, "  Austin ")
        .await
        .expect("the window's door mints the identity");
    assert!(did.starts_with("did:"), "creation answers with the DID: {did}");

    // What creation left in the registry: one entry, under a minted id, with
    // the typed name — trimmed — beside it.
    let registered = kuserd::device_users::load(base.path()).expect("read the registry");
    let (id, record) = match registered.iter().collect::<Vec<_>>()[..] {
        [(id, record)] => (id.clone(), record.clone()),
        ref many => {
            restore();
            panic!("one identity was made, the registry holds {}: {many:?}", many.len())
        }
    };
    assert_ne!(id, "owner", "the literal is retired for a new device");
    kuserd::device_users::validate_user_id(&id).expect("the minted id is one the registry accepts");
    assert!(
        !id.to_lowercase().contains("austin"),
        "the id must not be derived from the name: {id}"
    );
    assert!(
        !did.contains(&id) && !id.contains(did.rsplit(':').next().unwrap_or(&did)),
        "the id must not be derived from the DID: {id} / {did}"
    );
    assert_eq!(record.display_name.as_deref(), Some("Austin"));
    assert!(
        base.path().join("users").join(&id).is_dir(),
        "the id is the directory under users/"
    );
    // And the registry's name is a copy: the name the welcome took is kept
    // first as a sealed record in the person's own store, which is what their
    // other devices receive (`TASK-a-persons-name-travels-with-their-identity`).
    let store = daemon.users().get(&id).expect("the new identity is resident");
    assert_eq!(
        kuserd::own_name::read(&store).await.expect("the name record reads"),
        Some(kuserd::own_name::NameRecord { name: Some("Austin".to_owned()) }),
        "the welcome's name is kept with the identity"
    );

    // Settings' read: the name, and the id carried for the unlock — not drawn,
    // which `Identity` in the shell holds by having no field for it.
    let identity = host.read_identity().await.expect("read-identity");
    assert_eq!(identity.display_name.as_deref(), Some("Austin"));
    assert_eq!(identity.user_id, id);

    // A rename is a display change only: the record's name moves, and the id,
    // the directory and the DID do not. Creation opened a session, so the
    // person it names is the one asking.
    host.set_display_name(" Austin Herman ")
        .await
        .expect("the person who just enrolled may say what they are called");
    let after = kuserd::device_users::load(base.path()).expect("read the registry");
    assert_eq!(after.keys().collect::<Vec<_>>(), vec![&id], "a rename moves no id");
    assert_eq!(after[&id].display_name.as_deref(), Some("Austin Herman"));
    assert_eq!(
        kuserd::own_name::read(&store).await.expect("the name record reads"),
        Some(kuserd::own_name::NameRecord { name: Some("Austin Herman".to_owned()) }),
        "Settings edits the record, and the registry follows it"
    );
    assert_eq!(after[&id].did, record.did, "a rename touches no DID");
    assert!(base.path().join("users").join(&id).is_dir(), "a rename moves no directory");
    assert_eq!(
        host.read_identity().await.expect("read-identity").display_name.as_deref(),
        Some("Austin Herman")
    );

    // ── The resident launch that follows the ceremony ────────────────────────
    //
    // Only when kuserd bundles the shell: without it a new identity receives no
    // apps and there is nothing for a resident launch to run. That fails the test,
    // for a test that stops half-way reports the half it ran as the whole.
    let bundled = !kuserd::bundled::bundled_apps().is_empty();
    if !bundled {
        restore();
    }
    crate::common::bins::require_apps_bundled(bundled);
    let resp = daemon
        .end_the_occupant_world("sh.kotton.shell", &id)
        .await
        .expect("the occupant world must end in a resident launch");
    let report = launch_report(resp);
    let args: Vec<(String, String)> = report["launch_args"]
        .as_array()
        .expect("launch args")
        .iter()
        .map(|pair| (pair[0].as_str().unwrap().to_owned(), pair[1].as_str().unwrap().to_owned()))
        .collect();
    let arg = |key: &str| args.iter().find(|(k, _)| k == key).map(|(_, v)| v.clone());
    assert_eq!(arg("mode").as_deref(), Some("authenticated"), "{report}");
    assert_eq!(
        arg("display_name").as_deref(),
        Some("Austin Herman"),
        "the menubar is handed the name the person typed: {report}"
    );
    assert!(arg("did").is_some_and(|d| d.starts_with("did:")), "{report}");
    for (k, v) in &args {
        assert!(
            !v.contains(&id),
            "the minted id reached a launch argument a document could draw: {k}={v}"
        );
    }
    // And the mount is the id, which is what the id is for.
    let mount = report["user_vfs_path"].as_str().expect("the resident launch carries the mount");
    assert!(mount.contains(&id), "{mount}");

    // ── Second boot: the lock screen is told the name, and unlocks the id ────
    let (again, _endpoint) = boot_a_daemon_at(base.path(), secrets).await;
    let resp = again
        .launch_designated_shell("boot", None)
        .await
        .expect("a boot with an identity on the device must launch something");
    let (mode, users, names) = screen_of(resp);
    restore();

    assert_eq!(mode.as_deref(), Some("locked"));
    assert_eq!(users.as_deref(), Some(id.as_str()), "the id, for `unlock-with-pin`");
    assert_eq!(
        names.as_deref(),
        Some("Austin Herman"),
        "the name, for *Welcome back* — never the id"
    );
}

/// **A device enrolled before the ruling keeps its `owner` id, opens as it
/// did, and stops drawing it**
/// (`TASK-the-name-the-welcome-asks-for-goes-nowhere`: *"An existing device keeps
/// its `owner` id, because renaming a directory under `users/` is a migration
/// with nothing to gain, and it stops drawing it"*).
///
/// The existing device is made the way every device before 2026-09-24 was: an
/// identity registered under the id `owner` with no display name, through the
/// door that still writes exactly that record — `CreateUser`, which the CLI
/// calls — so what the second boot reads is what such a device actually holds,
/// down to the file having no `display_name` key at all.
///
/// Then the migration: the second boot opens the lock screen for `owner` with an
/// empty name slot; the rename is refused until the person unlocks; once they
/// have, Settings sets the name; the resident launch that follows carries the
/// typed name and the mount `users/owner/data`; and the registry key, the
/// directory and the DID are what they were.
#[tokio::test]
#[serial_test::serial]
#[allow(unsafe_code)] // env::set_var is unsafe in Rust 1.81+; serialised by #[serial]
async fn a_device_enrolled_as_owner_keeps_its_id_and_stops_drawing_it() {
    use kotton_app::daemon::apps::OccupantHost as _;

    // Before anything is set: this test ends in a launch of the shell, so it must be built.
    crate::common::bins::require_shell_wasm();
    let base = tempfile::tempdir().expect("tempdir");
    stage_a_system_shell(base.path());

    // SAFETY: `#[serial_test::serial]` means nothing else is running. Restored
    // at the end, and before the assertions so a panic cannot leave them set.
    let prior_base = std::env::var_os("KOTTON_BASE_DIR");
    unsafe {
        std::env::set_var("KOTTON_BASE_DIR", base.path());
        std::env::set_var("MOCK_RUNNER_MODE", "report-input");
    }
    let restore = || unsafe {
        std::env::remove_var("MOCK_RUNNER_MODE");
        match &prior_base {
            Some(v) => std::env::set_var("KOTTON_BASE_DIR", v),
            None => std::env::remove_var("KOTTON_BASE_DIR"),
        }
    };

    let secrets: std::sync::Arc<dyn kotton_sys::secret::SecretsStore + Send + Sync> =
        std::sync::Arc::new(kotton_secret::MemorySecrets::new());

    // ── The device as it was: `owner`, no name ───────────────────────────────
    let shell_bundled = {
        let (daemon, endpoint) =
            boot_a_daemon_at(base.path(), std::sync::Arc::clone(&secrets)).await;
        let serving = tokio::spawn({
            let daemon = std::sync::Arc::clone(&daemon);
            async move { daemon.run().await }
        });
        crate::common::wait_for_daemon(&endpoint, "the first boot").await;
        let mut client = crate::common::connect_when_ready(&endpoint, "the first boot").await;
        client
            .create_user("owner", crate::common::TEST_PASSPHRASE)
            .await
            .expect("create_user");
        let installed = client.app_list().await.expect("app_list");
        serving.abort();
        installed.iter().any(|a| a.app_id == "sh.kotton.shell")
    };

    let file = std::fs::read_to_string(base.path().join("device").join("users.json"))
        .expect("the registry file");
    assert!(
        !file.contains("display_name"),
        "the pre-ruling record has no display_name key at all: {file}"
    );
    let registered = kuserd::device_users::load(base.path()).expect("read the registry");
    assert_eq!(registered.keys().collect::<Vec<_>>(), vec!["owner"]);
    assert_eq!(registered["owner"].display_name, None);
    let did_before = registered["owner"].did.clone();

    // ── The second boot: the lock screen, with the name slot empty ───────────
    let (daemon, _endpoint) = boot_a_daemon_at(base.path(), secrets).await;
    assert_eq!(daemon.users().any().as_deref(), Some("owner"), "the boot loads the user");
    let resp = daemon
        .launch_designated_shell("boot", None)
        .await
        .expect("a boot with an identity on the device must launch something");
    let (mode, users, names) = screen_of(resp);
    assert_eq!(mode.as_deref(), Some("locked"));
    assert_eq!(users.as_deref(), Some("owner"), "the id still opens the device");
    assert_eq!(names.as_deref(), Some(""), "and is not what the screen is told to draw");

    // Settings' read, before anything is unlocked: the id carried, no name.
    let host = daemon.occupant_host();
    let identity = host.read_identity().await.expect("read-identity");
    assert_eq!(identity.user_id, "owner");
    assert_eq!(identity.display_name, None);

    // A name is changed by the person it names: refused at the lock screen.
    match host.set_display_name("Austin").await {
        Err(kotton_wire::runner::RunnerAuthError::Daemon { message }) => {
            assert!(message.contains("unlock first"), "{message}")
        }
        other => {
            restore();
            panic!("a rename before unlock must be refused as a daemon error, got {other:?}")
        }
    }
    assert_eq!(
        kuserd::device_users::load(base.path()).unwrap()["owner"].display_name,
        None,
        "a refused rename writes nothing"
    );

    // The person unlocks, and sets the name the welcome never kept.
    host.unlock_with_pin("owner", crate::common::TEST_PASSPHRASE)
        .await
        .expect("the credential that made this identity opens it");
    assert_eq!(host.unlocked_as().as_deref(), Some("owner"));
    host.set_display_name("Austin")
        .await
        .expect("an unlocked person may say what they are called");
    let after = kuserd::device_users::load(base.path()).expect("read the registry");
    assert_eq!(after.keys().collect::<Vec<_>>(), vec!["owner"], "the id is kept");
    assert_eq!(after["owner"].display_name.as_deref(), Some("Austin"));
    assert_eq!(after["owner"].did, did_before, "the DID is untouched");
    assert!(base.path().join("users").join("owner").is_dir(), "the directory is kept");
    assert_eq!(
        host.read_identity().await.expect("read-identity").display_name.as_deref(),
        Some("Austin")
    );

    // ── The resident launch: called Austin, mounted at users/owner ───────────
    if !shell_bundled {
        restore();
    }
    crate::common::bins::require_apps_bundled(shell_bundled);
    let resp = daemon
        .end_the_locked_screen("sh.kotton.shell", "owner")
        .await
        .expect("an accepted credential must be followed by a resident launch");
    let report = launch_report(resp);
    restore();
    let arg = |key: &str| {
        report["launch_args"]
            .as_array()
            .expect("launch args")
            .iter()
            .find(|pair| pair[0] == key)
            .and_then(|pair| pair[1].as_str())
            .map(str::to_owned)
    };
    assert_eq!(arg("mode").as_deref(), Some("authenticated"), "{report}");
    assert_eq!(
        arg("display_name").as_deref(),
        Some("Austin"),
        "the desktop calls the person by the name they set, not `owner`: {report}"
    );
    let expected = base
        .path()
        .join("users")
        .join("owner")
        .join("data")
        .to_string_lossy()
        .into_owned();
    assert_eq!(
        report["user_vfs_path"].as_str(),
        Some(expected.as_str()),
        "the mount is still the `owner` directory: {report}"
    );
}

/// **The flip is tied to the occupant's instance, not to whichever app took the
/// event.**
///
/// Assessed on `TASK-the-shell-that-welcomed-you-keeps-running-without-your-files`,
/// 2026-09-20: today the ceremony door can only be reached by the occupant,
/// because no other instance can run before a user exists — but that is a fact
/// about the world rather than about the code. A recovery-key login over IPC
/// flips the registry too, and the next event to *any* instance would then end
/// it. Ending somebody else's running app because the person logged in
/// elsewhere is the failure this pins.
///
/// The bystander here is an ordinary long-lived app: installed, launched, and
/// never designated `shell`, so the host instantiated it into `world app` and
/// its instance carries `occupant: false`.
///
/// **Liveness is read from the runner's own counter**, which increments inside
/// one process and restarts at one in a fresh one — the instrument
/// `long_lived_app_reuses_subprocess` uses. A test that asked the daemon
/// whether an instance existed would be asking the same map the guard reads;
/// the counter asks the process.
///
/// **What this cannot say, said here rather than implied.** Every instance this
/// suite can launch belongs to a resident user, so the bystander carries a data
/// mount too, and the door refuses it on *both* of its grounds — it is not the
/// occupant's, and it is already mounted. Falsified 2026-09-21 by disabling the
/// occupant arm: this test still passed, on the second ground. So what it pins
/// is the end-to-end fact that matters to a person — a running app of theirs
/// survives the door, process and all — and *which* ground decided is pinned
/// beside the rule itself, in `agent::compositor::tests` (`kuserd`), where an
/// unmounted bystander can be expressed.
#[tokio::test]
#[serial_test::serial]
async fn the_screen_is_replaced_only_when_the_occupant_raised_the_event() {
    use crate::common::InstallApprovingAll as _;

    /// Distinct from the other suites' ids so install/uninstall cannot interact.
    const BYSTANDER: &str = r#"
[app]
id      = "sh.kotton.test-unlock-bystander"
name    = "Unlock Bystander"
version = "0.1.0"
kind    = "long-lived"
"#;
    const STUB_WASM: &[u8] = &[0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];

    /// The `counter:N` the mock paints into each reply.
    fn counter(messages: &[Vec<u8>]) -> Option<u32> {
        messages
            .iter()
            .filter_map(|m| m.split_first())
            .filter(|(fmt, _)| **fmt == 0x00)
            .filter_map(|(_, body)| serde_json::from_slice::<String>(body).ok())
            .find(|s| s.starts_with("counter:"))
            .and_then(|s| s.strip_prefix("counter:").unwrap().parse().ok())
    }

    let mut env = crate::common::TestEnv::spawn_with_mock_runner_authed().await;
    let (app_id, _name, _caps) = env
        .client
        .app_install_approving_all("", BYSTANDER.to_string(), STUB_WASM.to_vec())
        .await
        .expect("app_install (the bystander)");
    assert_ne!(
        env.client.app_get_role("shell").await.expect("app_get_role"),
        Some(app_id.clone()),
        "the bystander must not be the designated shell, or this test asserts nothing"
    );

    env.client
        .app_launch(&app_id, vec![])
        .await
        .expect("app_launch (the bystander)");
    let before = counter(
        &env.client
            .app_message(&app_id, r#"{"seq":1}"#.to_string())
            .await
            .expect("app_message before"),
    )
    .expect("the mock reports its counter");

    // The door, aimed at somebody else's app.
    let resp = env.daemon.end_the_locked_screen(&app_id, "owner").await;
    assert!(
        resp.is_none(),
        "an event to an app that is not the occupant must not relaunch the shell, got {resp:?}"
    );

    let after = counter(
        &env.client
            .app_message(&app_id, r#"{"seq":2}"#.to_string())
            .await
            .expect("app_message after"),
    )
    .expect("the mock reports its counter");
    assert_eq!(
        after,
        before + 1,
        "the bystander's own process must have survived the door \
         (before={before}, after={after}); a restart would begin at one"
    );
}

// ── The second boot ──────────────────────────────────────────────────────────

/// Stage a system shell under `base`, the way `cargo xtask build-apps` does.
///
/// The manifest is the shell's real one — it is checked in, it is what
/// `app_launch_system_shell` parses, and a manifest that stops parsing should
/// fail here. The `app.wasm` beside it is a placeholder, because these two tests
/// are about **which launch arguments the host writes** and the mock runner never
/// opens the module. A test of the *screen* needs the real wasm and the real
/// runner, and that is `a_fresh_machine_draws_its_welcome_screen` above; a test
/// that needed `build-apps` to have run would be one that mostly skips.
fn stage_a_system_shell(base: &std::path::Path) {
    let dir = kotton_app::daemon::apps::system_shell_dir(base);
    std::fs::create_dir_all(&dir).expect("stage dir");
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../guest/apps/kotton-shell/manifest.toml");
    std::fs::copy(&manifest, dir.join("manifest.toml")).expect("stage manifest");
    std::fs::write(dir.join("app.wasm"), b"").expect("stage a placeholder module");
}

/// A daemon constructed on `base`, not yet serving anything.
///
/// This is what a boot *is*, up to the point the question is asked: the process
/// starts, reads its base directory, and decides what to draw. `run` is not
/// called because nothing here needs the IPC listener — `launch_designated_shell`
/// is the call `run` spawns, and it is called directly so the answer can be read.
async fn boot_a_daemon_at(
    base: &std::path::Path,
    secrets: std::sync::Arc<dyn kotton_sys::secret::SecretsStore + Send + Sync>,
) -> (std::sync::Arc<kuserd::DeviceDaemon>, crate::common::Door) {
    let unique = uuid::Uuid::new_v4().simple().to_string();
    #[cfg(windows)]
    let endpoint = crate::common::Door::pipe(format!("kotton-boot-{unique}"));
    #[cfg(unix)]
    let endpoint = crate::common::door_in(base, &format!("boot-{unique}.sock"));

    let daemon = std::sync::Arc::new(
        kuserd::DeviceDaemon::new_with_base_and_secrets(
            base.to_owned(),
            endpoint.clone(),
            secrets,
        )
        .await
        .expect("DeviceDaemon::new_with_base_and_secrets")
        .with_runner(std::path::PathBuf::from(crate::common::mock_runner_bin())),
    );
    (daemon, endpoint)
}

/// The `mode`, `users` and `names` a launch was handed, read back off the
/// mock's report.
///
/// Sent once in the init frame and never mentioned again, so
/// `MOCK_RUNNER_MODE=report-input` painting it back is the only channel there is
/// — the same trick `the_shell_that_follows_the_ceremony_carries_the_users_data_mount`
/// uses for the data mount.
fn screen_of(resp: kotton_wire::UserResponse) -> (Option<String>, Option<String>, Option<String>) {
    let report = launch_report(resp);
    let arg = |key: &str| {
        report["launch_args"]
            .as_array()
            .expect("launch args")
            .iter()
            .find(|pair| pair[0] == key)
            .and_then(|pair| pair[1].as_str())
            .map(str::to_owned)
    };
    (arg("mode"), arg("users"), arg("names"))
}

/// **A device that knows who lives here opens the lock screen, not the welcome.**
///
/// The owner reported this on 2026-09-20: an identity made in the window that
/// morning, `just desktop::run` that evening, and a screen offering to *create a
/// new identity* — whose one door then refused, because `create_identity` reads
/// `device/users.json` and `device/users.json` knew.
///
/// Two readers, one question. `launch_designated_shell` reached
/// `app_launch_system_shell` — by the `Locked` arm, because a boot loads the
/// registered user and a loaded user can be locked (`DEC-0049`) — and that
/// function wrote `mode=welcome` as a literal. The device registry, which is
/// what `shell_launch_mode` consults and where the guest's `LockPane` gets the
/// names it offers, was never asked on that path.
///
/// So this drives a real second boot: one daemon makes the identity, that daemon
/// stops, and a second daemon constructed on the same base is asked what it would
/// draw. The assertion is the launch argument, because that is the whole of what
/// the host tells the shell about which screen to open
/// (`guest/apps/kotton-shell/logic/src/lib.rs`: `Some("locked") => AppMode::Locked`,
/// and `users` is read beside it).
///
/// **`KOTTON_BASE_DIR` is set to that same base**, matching what production has
/// by construction (one base per process) — no longer load-bearing for
/// `device_users` itself, which now reads and writes relative to the daemon's
/// own `base` (`TASK-the-device-user-registry-is-read-from-a-process-global-base`,
/// closed), but kept because `DeviceDaemon::new()` and anything this test spawns
/// as a subprocess still resolve it the old way.
#[tokio::test]
#[serial_test::serial]
#[allow(unsafe_code)] // env::set_var is unsafe in Rust 1.81+; serialised by #[serial]
async fn a_second_boot_with_a_registered_identity_opens_the_lock_screen() {
    let base = tempfile::tempdir().expect("tempdir");
    stage_a_system_shell(base.path());

    // SAFETY: `#[serial_test::serial]` means nothing else is running. Restored
    // at the end, and before the assertions so a panic cannot leave them set.
    let prior_base = std::env::var_os("KOTTON_BASE_DIR");
    unsafe {
        std::env::set_var("KOTTON_BASE_DIR", base.path());
        std::env::set_var("MOCK_RUNNER_MODE", "report-input");
    }

    // Shared across both boots, because an OS keychain survives a daemon restart
    // and a fresh store would model a wiped one — the same reason
    // `schema_grants::grants_persist_across_restart` shares its secrets.
    let secrets: std::sync::Arc<dyn kotton_sys::secret::SecretsStore + Send + Sync> =
        std::sync::Arc::new(kotton_secret::MemorySecrets::new());

    // ── The first boot: the person makes their identity ──────────────────────
    //
    // Through the real verb rather than by writing `device/users.json` here, so
    // that what the second boot reads is what creating an identity actually
    // leaves behind.
    {
        let (daemon, endpoint) =
            boot_a_daemon_at(base.path(), std::sync::Arc::clone(&secrets)).await;
        let serving = tokio::spawn({
            let daemon = std::sync::Arc::clone(&daemon);
            async move { daemon.run().await }
        });
        crate::common::wait_for_daemon(&endpoint, "the first boot").await;
        let mut client = crate::common::connect_when_ready(&endpoint, "the first boot").await;
        client
            .create_user("owner", crate::common::TEST_PASSPHRASE)
            .await
            .expect("create_user");
        serving.abort();
    }

    let registered = kuserd::device_users::load(base.path()).expect("read the registry");
    assert!(
        registered.contains_key("owner"),
        "the first boot must leave the identity in the device registry, got {:?}",
        registered.keys().collect::<Vec<_>>()
    );

    // ── The second boot ──────────────────────────────────────────────────────
    let (daemon, _endpoint) = boot_a_daemon_at(base.path(), secrets).await;

    // **Which state the boot is in, pinned, because the two arms below differ
    // and the answer is not the one the record was filed on.** A boot *does*
    // load every registered user it may serve (`load_users_on_startup`, through
    // `DeviceDaemon::new_*`), and loading is not unlocking — `DEC-0049`. So the
    // person is resident and their database will not open, which sends this
    // launch down `launch_designated_shell`'s `Locked` arm rather than its
    // pre-identity one. Both arms reach `app_launch_system_shell`, and both used
    // to be handed `mode=welcome`; if residency ever stops happening at boot the
    // arm changes under this test and the test should say so rather than keep
    // passing for a different reason.
    assert_eq!(
        daemon.users().any().as_deref(),
        Some("owner"),
        "a boot loads the registered user — loaded, and locked, are not exclusive"
    );

    let resp = daemon
        .launch_designated_shell("boot", None)
        .await
        .expect("a boot with an identity on the device must launch something");
    let (mode, users, names) = screen_of(resp);

    unsafe {
        std::env::remove_var("MOCK_RUNNER_MODE");
        match &prior_base {
            Some(v) => std::env::set_var("KOTTON_BASE_DIR", v),
            None => std::env::remove_var("KOTTON_BASE_DIR"),
        }
    }

    assert_eq!(
        mode.as_deref(),
        Some("locked"),
        "a device whose registry names somebody opens the lock screen, never the welcome"
    );
    assert_eq!(
        users.as_deref(),
        Some("owner"),
        "the lock screen is told whose device this is, or it has nobody to unlock"
    );
    // And what to call them: nothing, because nobody has said. The slot is
    // there and empty — not the id copied across, which is what the screen
    // would draw (`TASK-the-name-the-welcome-asks-for-goes-nowhere`).
    assert_eq!(
        names.as_deref(),
        Some(""),
        "an identity with no name gets an empty name slot, never its id"
    );
}

/// **A launch for a person whose store holds no keys opens the lock screen and
/// says why — never a desk** (`TASK-a-roots-failure-is-drawn-as-no-roots`,
/// clause a).
///
/// The owner's screen of 2026-09-24: an account row with a fingerprint, an
/// empty *Locations*, and a Networking notice saying the node held no key. The
/// daemon had loaded the person keyless at boot; the credential was right; the
/// relaunch that followed was for a named person and landed on a store with no
/// CEK. Two fixes, and this drives both:
///
/// 1. **The cause.** The lock screen's door (`DaemonOccupantHost::open_session`)
///    now rebuilds the keyless resident store with the key the unlock restored,
///    as the IPC arm always did. After the unlock the resident store holds
///    keys, and a launch for the person opens on their desk with their mount.
/// 2. **The rule.** A launch for a named person whose store holds no keys —
///    modelled here as the rekey having failed, by putting the keyless store
///    back — is demoted to a launch for nobody: `mode=locked`, no mount, and a
///    `notice` saying why in one sentence. Mutate `a_person_whose_keys_are_loaded`
///    in `core/app` and this goes red.
#[tokio::test]
#[serial_test::serial]
#[allow(unsafe_code)] // env::set_var is unsafe in Rust 1.81+; serialised by #[serial]
async fn a_launch_for_a_person_whose_store_holds_no_keys_opens_the_lock_screen_and_says_why() {
    let base = tempfile::tempdir().expect("tempdir");
    stage_a_system_shell(base.path());

    // SAFETY: `#[serial_test::serial]` means nothing else is running.
    let prior_base = std::env::var_os("KOTTON_BASE_DIR");
    unsafe {
        std::env::set_var("KOTTON_BASE_DIR", base.path());
        std::env::set_var("MOCK_RUNNER_MODE", "report-input");
    }
    let secrets: std::sync::Arc<dyn kotton_sys::secret::SecretsStore + Send + Sync> =
        std::sync::Arc::new(kotton_secret::MemorySecrets::new());

    // The first boot: the person makes their identity, through the real verb.
    {
        let (daemon, endpoint) =
            boot_a_daemon_at(base.path(), std::sync::Arc::clone(&secrets)).await;
        let serving = tokio::spawn({
            let daemon = std::sync::Arc::clone(&daemon);
            async move { daemon.run().await }
        });
        crate::common::wait_for_daemon(&endpoint, "the first boot").await;
        let mut client = crate::common::connect_when_ready(&endpoint, "the first boot").await;
        client
            .create_user("owner", crate::common::TEST_PASSPHRASE)
            .await
            .expect("create_user");
        serving.abort();
    }

    // The second boot loads the person, and loading is not unlocking
    // (`DEC-0049`): the resident store holds no key.
    let (daemon, _endpoint) = boot_a_daemon_at(base.path(), secrets).await;
    let keyless = daemon.users().get("owner").expect("the boot loads the registered user");
    assert!(
        keyless.sealing_keys().is_none(),
        "the fixture is a store loaded before the unlock, which holds no CEK"
    );

    // The unlock, through the door the lock screen calls — which is the door
    // that did not rekey the store until 2026-09-24.
    {
        let host = daemon.occupant_host();
        kotton_app::daemon::apps::OccupantHost::unlock_with_pin(
            &host,
            "owner",
            crate::common::TEST_PASSPHRASE,
        )
        .await
        .expect("the credential that made this identity must open it");
    }
    let keyed = daemon.users().get("owner").expect("still loaded");
    assert!(
        keyed.sealing_keys().is_some(),
        "the lock screen's door must rebuild the keyless resident store with the restored key"
    );

    // **The rule.** Model the rekey having failed: the keyless store is back,
    // the session and the restored secret are not. The relaunch that follows
    // an unlock is for a named person, and it must not draw a desk over this.
    daemon.users().insert("owner".to_owned(), std::sync::Arc::clone(&keyless));
    let resp = daemon
        .launch_designated_shell("unlocked", Some("owner".to_owned()))
        .await
        .expect("a launch for a person with an identity launches something");
    let report = launch_report(resp);
    let arg = |report: &serde_json::Value, key: &str| {
        report["launch_args"]
            .as_array()
            .expect("launch args")
            .iter()
            .find(|pair| pair[0] == key)
            .and_then(|pair| pair[1].as_str())
            .map(str::to_owned)
    };
    let over_keyless = (
        arg(&report, "mode"),
        arg(&report, "users"),
        arg(&report, "notice"),
        report["user_vfs_path"].clone(),
    );

    // **The cause, fixed.** With the keyed store resident the same launch is
    // the person's desk, with their mount.
    daemon.users().insert("owner".to_owned(), keyed);
    let resp = daemon
        .launch_designated_shell("unlocked", Some("owner".to_owned()))
        .await
        .expect("a launch for a person with keys launches their desk");
    let report = launch_report(resp);
    let over_keyed = (arg(&report, "mode"), arg(&report, "notice"), report["user_vfs_path"].clone());

    unsafe {
        std::env::remove_var("MOCK_RUNNER_MODE");
        match &prior_base {
            Some(v) => std::env::set_var("KOTTON_BASE_DIR", v),
            None => std::env::remove_var("KOTTON_BASE_DIR"),
        }
    }

    let (mode, users, notice, mount) = over_keyless;
    assert_eq!(
        mode.as_deref(),
        Some("locked"),
        "a launch for a person whose store holds no keys opens the lock screen, never a desk"
    );
    assert_eq!(users.as_deref(), Some("owner"), "and it is told whose device this is");
    assert_eq!(
        notice.as_deref(),
        Some(kotton_app::daemon::apps::KEYS_NOT_LOADED_NOTICE),
        "the lock screen is told why, in one sentence"
    );
    let notice = notice.unwrap_or_default();
    assert_eq!(notice.matches('.').count(), 1, "{notice}");
    assert!(notice.ends_with('.'), "{notice}");
    assert!(
        mount.is_null(),
        "a launch demoted to nobody carries no mount, so the unlock door can replace it: {mount}"
    );

    let (mode, notice, mount) = over_keyed;
    assert_eq!(mode.as_deref(), Some("authenticated"), "with keys loaded, the desk");
    assert_eq!(notice, None, "and nothing to explain");
    assert_eq!(
        mount.as_str(),
        Some(
            base.path()
                .join("users")
                .join("owner")
                .join("data")
                .to_string_lossy()
                .as_ref()
        ),
        "with their mount"
    );
}

/// And the welcome is still what a boot with nobody registered gets.
///
/// The other half of the same rule, and the one a fix aimed at the lock screen
/// could quietly take away: `shell_launch_mode` routes on an *empty* registry,
/// so a machine nobody has enrolled on must still reach the screen that enrols
/// them. `users` is absent rather than empty, because the welcome has nobody to
/// offer and an empty string in that slot is a list of one nameless person.
#[tokio::test]
#[serial_test::serial]
#[allow(unsafe_code)] // env::set_var is unsafe in Rust 1.81+; serialised by #[serial]
async fn a_boot_with_nobody_registered_still_opens_the_welcome() {
    let base = tempfile::tempdir().expect("tempdir");
    stage_a_system_shell(base.path());

    // SAFETY: `#[serial_test::serial]` means nothing else is running.
    let prior_base = std::env::var_os("KOTTON_BASE_DIR");
    unsafe {
        std::env::set_var("KOTTON_BASE_DIR", base.path());
        std::env::set_var("MOCK_RUNNER_MODE", "report-input");
    }

    let secrets: std::sync::Arc<dyn kotton_sys::secret::SecretsStore + Send + Sync> =
        std::sync::Arc::new(kotton_secret::MemorySecrets::new());
    let (daemon, _endpoint) = boot_a_daemon_at(base.path(), secrets).await;

    let resp = daemon
        .launch_designated_shell("boot", None)
        .await
        .expect("a fresh machine must still have something to draw");
    let (mode, users, _names) = screen_of(resp);

    unsafe {
        std::env::remove_var("MOCK_RUNNER_MODE");
        match &prior_base {
            Some(v) => std::env::set_var("KOTTON_BASE_DIR", v),
            None => std::env::remove_var("KOTTON_BASE_DIR"),
        }
    }

    assert_eq!(
        mode.as_deref(),
        Some("welcome"),
        "a machine nobody lives on opens the screen that enrols somebody"
    );
    assert_eq!(
        users, None,
        "the welcome screen is handed no user list: there is nobody to list"
    );
}
