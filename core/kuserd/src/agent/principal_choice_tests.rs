// SPDX-License-Identifier: AGPL-3.0-or-later
//! No path chooses whose principal it acts for by "any loaded user" (#432).
//!
//! `UserRegistry::any` answered *any one loaded user*, in a `HashMap`'s order.
//! The web-shell gateway, the boot sidecars, the compositor channel and the
//! system install each took it as the user they act for, so on a device holding
//! two identities each acted for whichever one the map happened to yield.
//!
//! Every test here boots a daemon holding alice and bob, both unlocked
//! ([`alice_and_bob`]), and holds each path to the same rule: it acts for the
//! user it was given, or for the one loaded, and with two loaded and none given
//! it refuses. It never acts for the other one.

use super::session_read_tests::{a_connection, alice_and_bob};
use super::*;

const BOB_SESSION: &str = "bob-session";
const ALICE_SESSION: &str = "alice-session";

/// The user the web-shell gateway's token acts for, once its supervisor has
/// minted one, or `None` if none is minted within `within`.
///
/// The token is the gateway's whole authority: `supervise_khttpd` mints it into
/// the session map, as a gateway token, for the user it was started for. So
/// whose it is, is whom the gateway acts for. The bound is generous on every
/// platform: the mint is the supervisor's first act after one config read, a
/// few milliseconds after it is spawned.
async fn gateway_acts_for(ctx: &super::super::AgentContext, within: std::time::Duration) -> Option<String> {
    let until = std::time::Instant::now() + within;
    loop {
        let token = ctx.gateway_tokens.read().unwrap().iter().next().cloned();
        if let Some(token) = token {
            if let Some(user) = sessions::live_user(&ctx.sessions, &token) {
                return Some(user);
            }
        }
        if std::time::Instant::now() >= until {
            return None;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
}

/// `request` from the connection holding `token`.
async fn from(ctx: &super::super::AgentContext, token: &str, request: UserRequest) -> UserResponse {
    handle_request(ctx, request, Caller::anonymous(), a_connection(token))
        .await
        .expect("answered")
}

fn switch_the_web_shell_on(port: Option<u16>) -> UserRequest {
    UserRequest::WebShellSet { enabled: Some(true), port, bind: None, static_dir: None, allow: None }
}

/// **`WebShellSet` from bob's session starts the gateway for bob, never alice;
/// and while it serves bob, alice's `WebShellSet` is refused, naming bob, and
/// changes nothing.**
///
/// `WebShellSet` is a session verb, so the gate hands it bob's user, and that
/// is the user the gateway's token is minted for. A second person's
/// `WebShellSet` is refused rather than restarting the gateway as them or
/// reconfiguring the one bob is using: the port stays bob's.
///
/// On every platform. No `khttpd` sits beside a unit test's binary, so the
/// supervisor's spawns fail and it gives up after its third, about three
/// seconds in (`liveness`). The token is minted before each spawn, and
/// alice's request follows the first token by milliseconds.
#[tokio::test]
async fn web_shell_set_from_bobs_session_acts_for_bob_and_a_second_users_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let daemon = alice_and_bob(dir.path()).await;
    let ctx = daemon.agent_context();
    sessions::insert(&ctx.sessions, BOB_SESSION.to_string(), "bob".to_string());
    sessions::insert(&ctx.sessions, ALICE_SESSION.to_string(), "alice".to_string());

    let resp = from(&ctx, BOB_SESSION, switch_the_web_shell_on(None)).await;
    assert!(matches!(resp, UserResponse::Ok), "bob switches the web shell on: {resp:?}");
    let acts_for = gateway_acts_for(&ctx, std::time::Duration::from_secs(10)).await;
    assert_eq!(acts_for.as_deref(), Some("bob"), "the gateway bob switched on acts for bob");
    assert_eq!(super::super::khttpd_acts_for(&ctx.sidecar_states).as_deref(), Some("bob"));

    let port_before = kotton_device::config::ops::web_shell(ctx.device_db.as_ref()).await.unwrap().port;
    let resp = from(&ctx, ALICE_SESSION, switch_the_web_shell_on(Some(port_before.wrapping_add(1)))).await;
    match &resp {
        UserResponse::Error { message } => {
            assert!(message.contains("bob"), "the refusal names the user the gateway serves: {message}")
        }
        other => panic!("alice's WebShellSet while the gateway serves bob is refused, got {other:?}"),
    }
    let port_after = kotton_device::config::ops::web_shell(ctx.device_db.as_ref()).await.unwrap().port;
    assert_eq!(port_after, port_before, "the refused WebShellSet changed the gateway's configuration");
    for token in ctx.gateway_tokens.read().unwrap().iter() {
        assert_ne!(
            sessions::live_user(&ctx.sessions, token).as_deref(),
            Some("alice"),
            "a gateway token acts for alice, who switched nothing on"
        );
    }
    assert_eq!(
        super::super::khttpd_acts_for(&ctx.sidecar_states).as_deref(),
        Some("bob"),
        "the gateway still serves bob"
    );
}

/// **At boot, with two users loaded and no session to name one, the web-shell
/// gateway starts for nobody.**
///
/// The boot names no user, and with two loaded there is no one principal, so
/// `ensure_khttpd` starts nothing and says why in the log. On every platform:
/// the bound waits two seconds for a mint that, were one coming, would land in
/// milliseconds.
#[tokio::test]
async fn the_web_shell_at_a_two_user_boot_starts_for_nobody() {
    let dir = tempfile::tempdir().unwrap();
    let daemon = alice_and_bob(dir.path()).await;
    let ctx = daemon.agent_context();
    kotton_device::config::ops::set_web_shell(ctx.device_db.as_ref(), Some(true), None, None, None, None)
        .await
        .unwrap();

    let started = super::super::ensure_khttpd(&ctx, None).await;
    assert_eq!(started, super::super::Gateway::NobodyToServe, "a two-user boot starts no gateway");

    let acts_for = gateway_acts_for(&ctx, std::time::Duration::from_secs(2)).await;
    assert_eq!(acts_for, None, "a boot that names no user started the gateway for {acts_for:?}");
}

/// **The boot sidecars (ksyncd, kquicd) act for the one loaded user, and with
/// two loaded for nobody.**
#[tokio::test]
async fn a_two_user_boot_names_no_sidecar_user() {
    let dir = tempfile::tempdir().unwrap();
    let daemon = alice_and_bob(dir.path()).await;
    assert_eq!(daemon.sidecar_user(), None, "a two-user boot's sidecars act for nobody");
}

/// **The compositor channel, with two users loaded, opens neither one's
/// database.** It has no session to name a person, and a compositor cannot
/// know whose screen it is, so it refuses rather than guess; its records host
/// already did.
#[tokio::test]
async fn the_compositor_with_two_users_loaded_opens_neither_database() {
    let dir = tempfile::tempdir().unwrap();
    let daemon = alice_and_bob(dir.path()).await;
    let ctx = daemon.agent_context();

    let err = user_db_for_compositor(&ctx.runtime, &ctx.users, &ctx.user_dbs, &ctx.base)
        .await
        .expect_err("with two users loaded the compositor opens neither database");
    assert!(err.to_string().contains("2 users are loaded"), "the refusal says why: {err}");
}

/// **A system install (`AppInstall` with an empty `user_id`), with two users
/// loaded, is refused before it reaches either one's registry.**
///
/// It is session-less by design, so no session names whose install it is, and
/// with two loaded there is no one principal. The refusal is the principal
/// rule's, said before the manifest is read: it never picks a database to try.
#[tokio::test]
async fn a_system_install_with_two_users_loaded_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let daemon = alice_and_bob(dir.path()).await;
    let ctx = daemon.agent_context();

    let err = user_db_for_principal(&ctx.runtime, &ctx.users, &ctx.user_dbs, &ctx.base)
        .await
        .expect_err("with two users loaded the principal rule names nobody");
    assert!(err.to_string().contains("2 users are loaded"), "the refusal says why: {err}");

    let install = UserRequest::AppInstall {
        user_id: String::new(),
        manifest_toml: String::new(),
        wasm_bytes: vec![],
        approved: vec![],
        bindings: vec![],
    };
    let resp = handle_request(&ctx, install, Caller::anonymous(), a_connection("no-session")).await;
    let err = resp.expect_err("a two-user system install is refused");
    assert!(
        err.to_string().contains("2 users are loaded"),
        "refused by the principal rule, before any user's database is opened: {err}"
    );
}
