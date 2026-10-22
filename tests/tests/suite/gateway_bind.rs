// SPDX-License-Identifier: AGPL-3.0-or-later
//! Integration tests — a gateway binds the address its configuration names.
//!
//! [`TASK-gateway-bind-mode-is-inert`] was a policy that was read, stored, surfaced in
//! status output, and then not applied: `web-shell.bind` accepted `lan` and `public`
//! and bound `0.0.0.0` either way. The fix gave `khttpd` a `BindScope` and a source
//! allow-list. Nothing checked that it *uses* them, which is the same shape as the
//! original defect one step later — and `cargo xtask bind-check` cannot see it,
//! because it reports the sockets a test run opens and no test ran a gateway.
//!
//! So this one does. It starts a real `khttpd` against a real daemon and reads back
//! the address the process actually bound, rather than the address the config says it
//! should have.
//!
//! # Why the wide bind is not asserted here
//!
//! The obvious pair is `loopback` → `127.0.0.1` and `all` → `0.0.0.0`. The second half
//! cannot run in this suite: `KOTTON_PAIR_LOCAL_ONLY=1` promises the run opens nothing
//! off this machine, and a test that proves the daemon binds every interface is a test
//! that binds every interface. It is `#[ignore]`d, which is this repo's declaration
//! that a test needs the network, and `-- --include-ignored` runs it.
//!
//! # How the configuration reaches the gateway
//!
//! Not over IPC. `khttpd` authenticates with a gateway token, so its origin is `Remote`
//! (RFC-0035), and `WebShellStatus` is `Local`-tier because a gateway must never
//! reconfigure itself. The first version of these tests found that the same floor
//! stopped the gateway *reading* its configuration, so it ran on hardcoded defaults
//! whatever the operator set (`TASK-gateway-sidecars-cannot-reach-their-own-bootstrap`).
//!
//! The resolution kept the floor and removed the reach: `kuserd` reads the stored
//! configuration and hands it over in the environment at spawn
//! (`WebShell::spawn_env`), and the sidecar's IPC scope is one verb. So this test
//! stores a configuration through the operator's verb, asks the in-process daemon for
//! the environment it would spawn with — the same function `supervise_khttpd` calls —
//! and starts the real binary with it. Both halves of the hand-over are on the path
//! from the stored value to the bound socket.
//!
//! # What is still not covered here
//!
//! The daemon's *refusal* path — a stored value it cannot parse must stop it rather
//! than widen it — is not exercised. Reaching it needs a bad value in `device_config`,
//! and the only ways in are `WebShellSet`, which now validates and refuses it, or the
//! database directly, which means either making `device_config_db::set_key` public or
//! giving this crate a `sqlx` dependency. Neither is worth it for a path already
//! covered at the parser (`kotton_common::listen`, `an_unrecognised_bind_value_is_refused_not_guessed`)
//! and at the operator boundary (`quic_gateway::quic_gateway_set_and_status_roundtrip`).
//! What is untested is one `?` between them.
//!
//! That split is not arbitrary. The `loopback` case — the one that always runs — is the
//! **security-relevant direction**: it fails if the daemon widens its bind, which is
//! exactly the historical bug and the only direction that can expose a node. The
//! `all` case catches the opposite regression, a daemon that narrows and becomes
//! unreachable, which is a functionality failure rather than an exposure. The cheaper
//! test guards the more expensive mistake.


use crate::common::khttpd::{self, free_port, Gateway};
use crate::common::TestEnv;
use kotton_wire::{UserRequest, UserResponse};

async fn bound_addr_for(bind: &str, port: u16) -> (Gateway, String) {
    let mut env = TestEnv::spawn().await;
    env.client.create_user("gwbind", crate::common::TEST_PASSPHRASE).await.expect("create_user");
    let session = env.client.session_token.clone().expect("session token");

    let mut operator = kotton_ipc::IpcClient::<UserRequest, UserResponse>::connect(
        env.endpoint.clone(),
    )
    .await
    .expect("connect");
    match operator
        .send(&UserRequest::Authenticate {
            token: kotton_wire::ipc::SecretText::new(session),
            scope: None,
        })
        .await
        .expect("authenticate")
    {
        UserResponse::ActiveSession { .. } => {}
        other => panic!("unexpected auth response: {other:?}"),
    }
    let set = operator
        .send(&UserRequest::WebShellSet {
            enabled: Some(true),
            port: Some(port),
            bind: Some(bind.to_string()),
            static_dir: None,
            allow: None,
        })
        .await
        .expect("WebShellSet send");
    assert!(matches!(set, UserResponse::Ok), "WebShellSet: {set:?}");

    let stored = operator
        .send(&UserRequest::WebShellStatus)
        .await
        .expect("WebShellStatus send");
    match &stored {
        UserResponse::WebShellStatusResult { port: p, bind: b, .. } => {
            assert_eq!(*p, port, "the port did not persist");
            assert_eq!(b, bind, "the bind scope did not persist");
        }
        other => panic!("expected WebShellStatusResult, got {other:?}"),
    }

    khttpd::spawn(&env).await
}

#[tokio::test]
async fn a_loopback_gateway_binds_loopback() {
    let port = free_port();
    let (_gw, addr) = bound_addr_for("loopback", port).await;
    assert_eq!(
        addr,
        format!("127.0.0.1:{port}"),
        "a gateway told `loopback` must bind loopback, not {addr}",
    );
}

/// A literal address is honoured as written, which no named scope can prove: `all` and
/// `loopback` are two branches a daemon could satisfy by accident, a specific address
/// has to be carried through.
///
/// `127.0.0.1` again rather than a second host address, because the whole `127.0.0.0/8`
/// block is only reliably bindable on Linux — macOS answers on `127.0.0.1` alone unless
/// an alias was added.
#[tokio::test]
async fn a_literal_address_is_bound_as_written() {
    let port = free_port();
    let (_gw, addr) = bound_addr_for("127.0.0.1", port).await;
    assert_eq!(addr, format!("127.0.0.1:{port}"));
}

/// Told `all`, the gateway binds every interface.
///
/// `#[ignore]`d because proving it means opening a socket off this machine, which is
/// the one thing `KOTTON_PAIR_LOCAL_ONLY=1` promises the suite does not do — the same
/// reason the mDNS daemon tests and the v6-only pairing test are ignored.
/// `-- --include-ignored` runs it, and `bind-check` will report the socket when it does.
#[tokio::test]
#[ignore = "binds 0.0.0.0 — the wide bind is the property under test"]
async fn a_wide_gateway_binds_every_interface() {
    let port = free_port();
    let (_gw, addr) = bound_addr_for("all", port).await;
    assert_eq!(
        addr,
        format!("0.0.0.0:{port}"),
        "a gateway told `all` must bind every interface, not {addr}",
    );
}
