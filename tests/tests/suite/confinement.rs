// SPDX-License-Identifier: AGPL-3.0-or-later
//! The capability check is on the path an app actually takes.
//!
//! `TASK-the-app-sandbox-is-imported-by-nothing` found that `kuserd` links
//! nothing of `kotton-wasm`, the crate holding `check_grant`, and asked whether
//! the sandbox is on the path an app takes or ahead of its integration. It is
//! on the path — as a **process**, not a library. The daemon spawns
//! `kotton-runner`, the crate's binary, and holds both ends of its pipes
//! (RFC-0082 rule 6); the runner builds the linker from what the user approved
//! at install, and an interface the user did not approve is not present to be
//! named. The daemon never links the crate, and should not: that is the
//! confinement boundary, and it belongs between two processes.
//!
//! This is the test the record asked for, through every layer that is real:
//! a real `kuserd`, the real `kotton-runner`, and a real component that asks
//! for two capabilities. The user approves one. The guest cannot reach the
//! other. The same binary, approved both, launches — so the refusal is the
//! withheld authority and nothing else.
//!
//! Needs `cargo build --bin kotton-runner` and `cargo xtask build-apps`, which
//! `just test` runs. Either missing fails loudly by name rather than passing
//! quietly, because a confinement test that skips itself is a paper gate.

use crate::common::{InstallApprovingAll, TestEnv, TEST_PASSPHRASE};
use kotton_schemas::CapabilityTarget;

const USER: &str = "owner";

/// The probe fixture, built by `cargo xtask build-apps`.
fn probe() -> (String, Vec<u8>) {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/probe-app");
    let manifest = std::fs::read_to_string(dir.join("manifest.toml")).expect("probe manifest");
    let wasm_path = dir.join("app.wasm");
    let wasm = std::fs::read(&wasm_path).unwrap_or_else(|e| {
        panic!(
            "the probe component is not built, so this test cannot run a real guest.\n  \
             missing: {} ({e})\n  \
             fix:     cargo xtask build-apps",
            wasm_path.display()
        )
    });
    (manifest, wasm)
}

/// Grant an app one capability and show it cannot reach a second.
#[tokio::test]
async fn a_guest_cannot_reach_what_the_user_did_not_approve() {
    let mut env = TestEnv::spawn_with_real_runner().await;
    env.client
        .create_user(USER, TEST_PASSPHRASE)
        .await
        .expect("create_user (authenticates the connection)");
    let (manifest, wasm) = probe();

    // The real ceremony: preview what the guest asks for, then approve a
    // subset — the apps grant, and not the schema one. (It was the files
    // grant until 2026-09-24; the probe runs one-shot, where a files grant
    // reaches nothing, so it asks for `apps.launch` instead.)
    let preview = env
        .client
        .app_install_preview(USER, manifest.clone(), wasm.clone())
        .await
        .expect("app_install_preview");
    let apps_only: Vec<_> = preview
        .requested
        .iter()
        .filter(|g| matches!(g.target, CapabilityTarget::AppLaunch))
        .cloned()
        .collect();
    assert!(
        !apps_only.is_empty() && apps_only.len() < preview.requested.len(),
        "the probe must ask for apps and for something else, or this proves nothing: {:?}",
        preview.requested
    );
    let (app_id, _, _) = env
        .client
        .app_install(USER, manifest.clone(), wasm.clone(), apps_only, vec![])
        .await
        .expect("install approving apps only");

    let err = env
        .client
        .app_launch(&app_id, vec![])
        .await
        .expect_err("a guest importing schema, approved only for apps, must not launch");
    let text = err.to_string();
    assert!(
        text.contains("kotton:app/schema"),
        "the refusal should name the interface the user withheld, got: {text}"
    );
    assert!(
        !text.contains("kotton:app/apps"),
        "apps was approved, so it must not be what the linker is missing: {text}"
    );

    // The control: the same component, approved everything it asked for,
    // launches and runs its `on-launch` against both interfaces.
    let (app_id, _, _) = env
        .client
        .app_install_approving_all(USER, manifest, wasm)
        .await
        .expect("install approving all");
    env.client
        .app_launch(&app_id, vec![])
        .await
        .expect("the same guest launches once both capabilities are approved");
}
