// SPDX-License-Identifier: AGPL-3.0-or-later
//! Integration tests — IPC hardening (RFC-0006)
//!
//! Covers two security properties:
//!
//! 1. **Frame size cap** (`MAX_FRAME_LEN = 32 MiB`): a client that sends an
//!    oversized length prefix gets its connection closed by the daemon.
//!
//! 2. **Scoped tokens**: when `Authenticate { scope: Some([...]) }` is used,
//!    only the listed request variants are permitted.  Any other variant
//!    receives `UserResponse::NotInScope` and the connection remains open.


use crate::common::TestEnv;
use kotton_sys::ipc::Connection;
use kotton_wire::{UserRequest, UserResponse};
use kotton_ipc::OsConnection;
use kotton::KottonClient;
use std::io;

const USER: &str = "bob";

/// A well-formed whole-file `ReadFile` range (RFC-0048). These tests assert
/// **scope** enforcement, which happens before the range is honoured, so the
/// window only has to be valid, not meaningful.
fn read_file(path: &str) -> UserRequest {
    UserRequest::ReadFile {
        user_id: USER.to_string(),
        path: path.to_string(),
        offset: 0,
        length: 4096,
    }
}

/// A well-formed single-chunk `WriteFile` (RFC-0048): one chunk that is the
/// whole file, with the content hash the receiver reassembles against.
fn write_file(path: &str, data: Vec<u8>) -> UserRequest {
    let content_hash = blake3::hash(&data).to_hex().to_string();
    UserRequest::WriteFile {
        user_id: USER.to_string(),
        path: path.to_string(),
        offset: 0,
        total_size: data.len() as u64,
        content_hash,
        data,
    }
}

// ── frame size cap ───────────────────────────────────────────────────────────

/// Sending a length prefix of 32 MiB + 1 causes the daemon to close the
/// connection without allocating the oversized buffer.
#[tokio::test]
async fn oversized_frame_closes_connection() {
    let env = TestEnv::spawn().await;

    // Use the platform IPC connection (handles OS-specific path formatting).
    let mut raw = OsConnection::connect(&env.endpoint)
        .await
        .expect("OsConnection::connect");

    // Write a length prefix just over MAX_FRAME_LEN (32 * 1024 * 1024).
    let oversized_len: u32 = 32 * 1024 * 1024 + 1;
    raw.write(&oversized_len.to_le_bytes())
        .await
        .map_err(io::Error::other)
        .expect("write length prefix");

    // The daemon should close the connection; any subsequent read returns 0.
    let mut buf = [0u8; 4];
    let n = raw
        .read(&mut buf)
        .await
        .map_err(io::Error::other)
        .expect("read after oversized frame");
    assert_eq!(n, 0, "daemon must close connection after oversized frame");
}

// ── scoped tokens ────────────────────────────────────────────────────────────

/// Authenticating with `scope: Some(["ReadFile"])` allows `ReadFile` but
/// returns `NotInScope` for `WriteFile`.
#[tokio::test]
async fn scoped_token_enforces_allow_list() {
    let mut env = TestEnv::spawn().await;

    // Create a user and capture the session token.
    env.client.create_user(USER, crate::common::TEST_PASSPHRASE).await.expect("create_user");
    let token = env.client.session_token.clone().expect("session token");

    // Open a second connection and authenticate with a narrow scope.
    let mut scoped = KottonClient::connect_to(env.endpoint.clone())
        .await
        .expect("connect_to");

    // Authenticate with scope restricted to ReadFile.
    scoped
        .authenticate_scoped(&token, Some(vec!["ReadFile".to_string()]))
        .await
        .expect("authenticate_scoped");

    // ReadFile with a path that won't exist — we just need a protocol-level
    // response, not a successful read.  NotInScope would be wrong here.
    let resp = scoped
        .inner()
        .send(&read_file("/nonexistent"))
        .await
        .expect("send ReadFile");
    assert!(
        !matches!(resp, UserResponse::NotInScope),
        "ReadFile must be allowed by scope, got NotInScope"
    );

    // WriteFile must be rejected.
    let resp = scoped
        .inner()
        .send(&write_file("/test.txt", vec![]))
        .await
        .expect("send WriteFile");
    assert!(
        matches!(resp, UserResponse::NotInScope),
        "WriteFile must be blocked by scope, got {resp:?}"
    );
}

/// Authenticating with `scope: None` (full access) lets all requests through.
#[tokio::test]
async fn no_scope_allows_all_requests() {
    let mut env = TestEnv::spawn().await;

    env.client.create_user(USER, crate::common::TEST_PASSPHRASE).await.expect("create_user");
    let token = env.client.session_token.clone().expect("session token");

    let mut conn = KottonClient::connect_to(env.endpoint.clone())
        .await
        .expect("connect_to");

    conn.authenticate(&token)
        .await
        .expect("authenticate (scope: None)");

    // Both ReadFile and WriteFile must be allowed (even if they return errors
    // for missing files — they must NOT return NotInScope).
    let resp = conn
        .inner()
        .send(&read_file("/nonexistent"))
        .await
        .expect("send ReadFile");
    assert!(
        !matches!(resp, UserResponse::NotInScope),
        "ReadFile must not return NotInScope when scope is None"
    );

    let resp = conn
        .inner()
        .send(&write_file("/test.txt", vec![]))
        .await
        .expect("send WriteFile");
    assert!(
        !matches!(resp, UserResponse::NotInScope),
        "WriteFile must not return NotInScope when scope is None"
    );
}

/// A scoped connection with an empty allow-list (`scope: Some([])`) is
/// treated as full access (no restrictions).
#[tokio::test]
async fn empty_scope_allows_all_requests() {
    let mut env = TestEnv::spawn().await;

    env.client.create_user(USER, crate::common::TEST_PASSPHRASE).await.expect("create_user");
    let token = env.client.session_token.clone().expect("session token");

    let mut conn = KottonClient::connect_to(env.endpoint.clone())
        .await
        .expect("connect_to");

    conn.authenticate_scoped(&token, Some(vec![]))
        .await
        .expect("authenticate_scoped (empty scope)");

    let resp = conn
        .inner()
        .send(&write_file("/test.txt", vec![]))
        .await
        .expect("send WriteFile");
    assert!(
        !matches!(resp, UserResponse::NotInScope),
        "empty scope must not restrict anything, got NotInScope"
    );
}

// ── trust-origin floor (RFC-0035) ────────────────────────────────────────────

/// RFC-0035: the trust floor is keyed on connection **origin** (bound from the
/// credential at `Authenticate`), not on scope-presence. A **Local** client may
/// invoke a `Local`-tier op it has scoped itself to — there is no forgeable
/// `explicitly_scoped` carve-out to abuse, because `Local` origin clears the floor
/// by definition. (This connection holds a *user* token, so it is `Local`; the old
/// test mislabelled it a "gateway" — exactly the scope-presence ≠ remote conflation
/// RFC-0035 removes.)
///
/// The complementary case — a **Remote** (gateway-origin) connection blocked from a
/// `Local`-tier op *even if it lists the op in its scope* (the actual #22 fix) —
/// needs a gateway-origin session in the harness. Tracked in
/// `TASK-no-gateway-origin-session-in-the-harness`. The floor logic itself is
/// unit-tested in `kotton-wire` (`ConnTrustOrigin` ordering + `required_trust`).
#[tokio::test]
async fn local_scoped_conn_reaches_its_scoped_op() {
    let mut env = TestEnv::spawn().await;

    env.client.create_user(USER, crate::common::TEST_PASSPHRASE).await.expect("create_user");
    let token = env.client.session_token.clone().expect("session token");

    let mut scoped = KottonClient::connect_to(env.endpoint.clone())
        .await
        .expect("connect_to");

    // StorageReload is a Local-tier op that goes through the
    // dispatch floor — the case this test exercises. (PairStart, the old choice,
    // was retired with the static–static seal.)
    scoped
        .authenticate_scoped(&token, Some(vec!["StorageReload".to_string()]))
        .await
        .expect("authenticate_scoped");

    let resp = scoped
        .inner()
        .send(&UserRequest::StorageReload {
            user_id: USER.to_string(),
        })
        .await
        .expect("send StorageReload");

    // Local origin clears the floor and StorageReload is in scope → NOT blocked.
    assert!(
        !matches!(resp, UserResponse::NotInScope),
        "a Local connection scoped to StorageReload should reach it (no carve-out abuse); got {resp:?}"
    );
}

/// The IPC endpoint used by the daemon is a named pipe / Unix socket path,
/// not a TCP address. This test confirms the endpoint does not look like a
/// raw TCP socket (e.g. `127.0.0.1:PORT` or `0.0.0.0:PORT`) which would
/// bypass OS-level access controls enforced by the named pipe / socket file.
#[tokio::test]
async fn ipc_endpoint_is_not_tcp() {
    use kotton_sys::ipc::IpcEndpoint;
    let env = TestEnv::spawn().await;

    // A TCP address starts with a digit (IPv4) or `[` (IPv6).
    let looks_like_tcp = match &env.endpoint {
        #[cfg(unix)]
        IpcEndpoint::UnixSocket(p) => p
            .to_string_lossy()
            .chars()
            .next()
            .map(|c: char| c.is_ascii_digit() || c == '[')
            .unwrap_or(false),
        #[cfg(windows)]
        IpcEndpoint::NamedPipe(s) => s
            .chars()
            .next()
            .map(|c: char| c.is_ascii_digit() || c == '[')
            .unwrap_or(false),
    };

    assert!(
        !looks_like_tcp,
        "IPC endpoint must be a named pipe / socket path, not a TCP address: {:?}",
        env.endpoint
    );
}

/// C2 regression: control-plane requests carry no `user_id`, so the old
/// `target_user_id().is_some()` gate skipped the session check and they
/// dispatched with **no session at all** — enough to grant an evil app access to
/// the user's data while the screen was locked. `SchemaGrantSet` must now be
/// refused without an authenticated session, and permitted with one.
#[tokio::test]
async fn control_plane_requires_a_session() {
    let mut env = TestEnv::spawn().await;

    // A fresh, UNauthenticated connection to the daemon.
    let mut conn = KottonClient::connect_to(env.endpoint.clone())
        .await
        .expect("connect_to");

    let grant = || UserRequest::SchemaGrantSet {
        app_id: "com.evil".to_string(),
        nsid: "sh.kotton.contacts".to_string(),
        can_read: true,
        can_write: true,
        can_register: false,
    };

    // Without a session the control-plane op is refused outright.
    let resp = conn
        .inner()
        .send(&grant())
        .await
        .expect("send SchemaGrantSet (unauthenticated)");
    assert!(
        matches!(resp, UserResponse::NoActiveSession),
        "control-plane SchemaGrantSet must require a session, got {resp:?}"
    );

    // After authenticating, it is no longer refused for lack of a session.
    env.client.create_user(USER, crate::common::TEST_PASSPHRASE).await.expect("create_user");
    let token = env.client.session_token.clone().expect("session token");
    conn.authenticate(&token).await.expect("authenticate");

    let resp = conn
        .inner()
        .send(&grant())
        .await
        .expect("send SchemaGrantSet (authenticated)");
    assert!(
        !matches!(resp, UserResponse::NoActiveSession),
        "authenticated SchemaGrantSet must not be refused for lack of a session, got {resp:?}"
    );
}
