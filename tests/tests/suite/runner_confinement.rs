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
//! all"*, which is that record's own phrasing: the mock runner these tests launch
//! instantiates no component at all.
//!
//! **These prove that the daemon's spawn paths ask for the confinement at all.** They
//! launch through `app_launch`, one app per spawn path — `spawn_runner` for a one-shot
//! app, `open_long_lived_runner` for a long-lived one and the occupant — and read back
//! what the kernel told the process the daemon spawned. An unconfined runner does
//! everything a confined one does, so no other app test in the suite holds this half by
//! passing: deleting a `confine_runner` call leaves them green.
//!
//! On a platform `core/proc` has no provider for, the runner keeps wasmtime as
//! its only layer and these tests fail — which is the true answer for that
//! platform, and the question escalated on
//! `TASK-windows-cannot-confine-a-guest-so-kotton-will-not-run-one-there`.

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
/// failure).
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
