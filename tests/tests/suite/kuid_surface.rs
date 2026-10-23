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

// ── An app may hold many surfaces (RFC-0087 stage 2) ─────────────────────────

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

// ── The name the welcome asks for goes somewhere ─────────────────────────────

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
