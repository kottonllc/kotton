// SPDX-License-Identifier: AGPL-3.0-or-later
//! kquicd — Kotton QUIC gateway sidecar (RFC-0015)
//!
//! # Responsibilities
//! - Authenticate to `kuserd` with the bootstrap token in `KQUICD_BOOTSTRAP_TOKEN`.
//! - Fetch the device Ed25519 signing key via `GetDeviceCert` and build the
//!   mTLS server certificate.
//! - Fetch the paired-client allowlist via `GetAuthorizedClients` and build a
//!   `PairedDeviceVerifier`.
//! - Bind a `quinn` QUIC server on the configured port (default 7443).
//! - Accept incoming mTLS connections; for each incoming bidirectional stream,
//!   forward the request to `kuserd` via IPC and return the response, after
//!   checking the RFC-0035 trust floor (`UserRequest::required_trust`).
//! - Refresh the authorized-client allowlist every 60 seconds.
//! - Exit cleanly (status 0) when supervision is no longer needed.

use ed25519_dalek::SigningKey;
use kotton_sys::ipc::IpcEndpoint;
use kotton_ipc::IpcClient;
use kotton_net::{
    build_peer_server_config, extract_ed25519_pubkey_from_cert, Ed25519DeviceCert,
    PairedDeviceVerifier,
};
use kotton_wire::{RemoteRequest, UserRequest, UserResponse};
use kotton_common::kuserd_ipc_name;
use quinn::Endpoint;
use std::collections::HashSet;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, RwLock};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Requested scope for the kquicd administrative IPC connection.
/// Phase 1 only calls these variants — no broader access is needed.
const KQUICD_SCOPE: &[&str] = &[
    "GetActiveSession",
    "GetDeviceCert",
    "GetAuthorizedClients",
    "QuicGatewayStatus",
];

/// Default QUIC gateway port.
const DEFAULT_PORT: u16 = 7443;

/// Maximum QUIC stream frame size: 4 MiB.
const MAX_FRAME_BYTES: u32 = 4 * 1024 * 1024;

/// Authorized-client refresh interval.
const REFRESH_SECS: u64 = 60;

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> io::Result<()> {
    // Both gateways declared `tracing-subscriber` and never initialised it, so every
    // `info!` and `warn!` in this binary — including the one that says the socket is
    // reachable from off this machine — was written to nowhere. RUST_LOG still wins;
    // the default is `info` rather than `EnvFilter`'s `error`, because a gateway that
    // will not say what it bound is a gateway nobody can check.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_target(false)
        .init();
    tracing_log::LogTracer::init().ok();

    let token = std::env::var("KQUICD_BOOTSTRAP_TOKEN")
        .map_err(|_| io::Error::other("KQUICD_BOOTSTRAP_TOKEN not set"))?;
    // Note: std::env::remove_var is unsafe in Rust 1.82+. The token is a
    // single-use UUID with no value after the first authentication.

    let endpoint = build_ipc_endpoint()?;

    // ── Administrative IPC connection (setup + periodic refresh) ────────────
    let mut admin: IpcClient<UserRequest, UserResponse> =
        IpcClient::connect(endpoint.clone()).await?;

    let scope: Option<Vec<String>> = Some(KQUICD_SCOPE.iter().map(|s| s.to_string()).collect());
    match admin
        .send(&UserRequest::Authenticate {
            token: kotton_wire::ipc::SecretText::new(token.clone()),
            scope,
        })
        .await?
    {
        UserResponse::ActiveSession { user_id } => {
            tracing::info!(%user_id, "kquicd authenticated");
        }
        UserResponse::NoActiveSession => {
            return Err(io::Error::other("bootstrap token rejected"));
        }
        UserResponse::Error { message } => {
            return Err(io::Error::other(format!("auth error: {message}")));
        }
        other => {
            return Err(io::Error::other(format!(
                "unexpected auth response: {other:?}"
            )));
        }
    }

    let user_id = match admin.send(&UserRequest::GetActiveSession).await? {
        UserResponse::ActiveSession { user_id } => user_id,
        _ => return Err(io::Error::other("failed to resolve active session")),
    };

    // ── Device certificate ───────────────────────────────────────────────────
    let signing_key_bytes = match admin
        .send(&UserRequest::GetDeviceCert {
            user_id: user_id.clone(),
        })
        .await?
    {
        UserResponse::DeviceCert { signing_key_bytes } => signing_key_bytes,
        other => {
            return Err(io::Error::other(format!(
                "GetDeviceCert unexpected response: {other:?}"
            )));
        }
    };

    let key_arr: [u8; 32] = signing_key_bytes
        .expose()
        .try_into()
        .map_err(|_| io::Error::other("signing key must be 32 bytes"))?;
    let signing_key = SigningKey::from_bytes(&key_arr);
    let device_cert = Ed25519DeviceCert::from_signing_key(&signing_key)
        .map_err(|e| io::Error::other(format!("cert build failed: {e}")))?;

    // ── Authorized-client allowlist ──────────────────────────────────────────
    let initial_keys = fetch_allowed_keys(&mut admin, &user_id).await?;
    let allowed_keys: Arc<RwLock<HashSet<[u8; 32]>>> =
        Arc::new(RwLock::new(initial_keys));

    // ── QUIC gateway config ──────────────────────────────────────────────────
    let (port, bind_mode, allow_raw) = match admin.send(&UserRequest::QuicGatewayStatus).await? {
        UserResponse::QuicGatewayStatusResult {
            port, bind, allow, ..
        } => (port, bind, allow),
        _ => (DEFAULT_PORT, "loopback".to_string(), None),
    };

    // Refuse to start on a bind setting we cannot honour, rather than falling back to
    // a wider one. The old code had no error path here because both of its branches
    // were the same address.
    let exposure = kotton_common::listen::Exposure::parse(&bind_mode, allow_raw.as_deref())
        .map_err(|e| io::Error::other(format!("quic-gateway.bind / quic-gateway.allow: {e}")))?;
    if let Some(replacement) = exposure.deprecated {
        tracing::warn!(
            stored = %bind_mode,
            replacement,
            "quic-gateway.bind uses a deprecated spelling; it now means what it always said"
        );
    }

    let bind_addr: SocketAddr = {
        let ip: IpAddr = IpAddr::V4(exposure.scope.bind_ipv4().ok_or_else(|| {
            io::Error::other(format!(
                "quic-gateway.bind is {}, but this listener binds IPv4",
                exposure.scope
            ))
        })?);
        SocketAddr::new(ip, port)
    };

    // ── Build QUIC server config ─────────────────────────────────────────────
    // rustls default ring/aws-lc provider.
    let provider = Arc::new(
        rustls::crypto::ring::default_provider(),
    );
    let verifier = PairedDeviceVerifier::new(Arc::clone(&allowed_keys), Arc::clone(&provider));
    let server_config = build_peer_server_config(
        &device_cert,
        verifier,
        Arc::clone(&provider),
        Some(std::time::Duration::from_secs(30)),
    )
    .map_err(|e| io::Error::other(format!("QUIC server config: {e}")))?;

    let quic_endpoint = Endpoint::server(server_config, bind_addr)
        .map_err(|e| io::Error::other(format!("QUIC bind failed: {e}")))?;
    let local_addr = quic_endpoint
        .local_addr()
        .map_err(|e| io::Error::other(format!("local addr: {e}")))?;
    let admits = if exposure.allow.is_unrestricted() {
        "any source".to_string()
    } else {
        exposure
            .allow
            .blocks()
            .iter()
            .map(|b| b.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    };
    tracing::info!(%local_addr, scope = %exposure.scope, admits = %admits, "kquicd QUIC gateway listening");
    if exposure.scope.is_offhost() {
        tracing::warn!(%local_addr, "kquicd is reachable from off this machine");
    }
    let allow = exposure.allow;

    // ── Background allowlist refresh ─────────────────────────────────────────
    {
        let keys = Arc::clone(&allowed_keys);
        let token2 = token.clone();
        let endpoint2 = endpoint.clone();
        let user_id2 = user_id.clone();
        tokio::spawn(async move {
            let mut ticker =
                tokio::time::interval(std::time::Duration::from_secs(REFRESH_SECS));
            ticker.tick().await; // discard immediate first tick
            loop {
                ticker.tick().await;
                match refresh_allowed_keys(&token2, &endpoint2, &user_id2).await {
                    Ok(new_keys) => {
                        *keys.write().unwrap() = new_keys;
                        tracing::debug!("kquicd: allowlist refreshed");
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "kquicd: allowlist refresh failed");
                    }
                }
            }
        });
    }

    // ── Accept loop ──────────────────────────────────────────────────────────
    loop {
        let incoming = match quic_endpoint.accept().await {
            Some(c) => c,
            None => {
                tracing::info!("kquicd: QUIC endpoint closed; exiting");
                return Ok(());
            }
        };

        // Refused before the handshake, so a source outside the guest list costs no
        // crypto. The allowlist of paired device keys below remains the real control;
        // this narrows who may attempt it at all.
        if !allow.permits(incoming.remote_address().ip()) {
            tracing::debug!(peer = %incoming.remote_address(), "refused: source outside quic-gateway.allow");
            incoming.refuse();
            continue;
        }

        let conn = match incoming.await {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(error = %e, "kquicd: incoming connection failed (TLS rejected or network error)");
                continue;
            }
        };

        let token3 = token.clone();
        let endpoint3 = endpoint.clone();
        let user_id3 = user_id.clone();
        tokio::spawn(handle_connection(conn, token3, endpoint3, user_id3));
    }
}

/// Exchange the verified peer DID for a session kuserd minted **for that peer**.
///
/// kuserd re-checks that the DID is a currently authorised client; it cannot
/// re-derive it, because it did not observe the handshake. That asymmetry is the
/// named trust boundary in RFC-0043 — kquicd is trusted to report who it
/// authenticated, exactly as it is already trusted to perform the handshake.
async fn mint_principal_session(
    endpoint: &IpcEndpoint,
    bootstrap_token: &str,
    user_id: &str,
    pubkey_hex: &str,
) -> io::Result<String> {
    let mut ipc: IpcClient<UserRequest, UserResponse> =
        IpcClient::connect(endpoint.clone()).await?;

    match ipc
        .send(&UserRequest::Authenticate {
            token: kotton_wire::ipc::SecretText::new(bootstrap_token.to_string()),
            scope: None,
        })
        .await?
    {
        UserResponse::ActiveSession { .. } => {}
        other => return Err(io::Error::other(format!("bootstrap auth failed: {other:?}"))),
    }

    match ipc
        .send(&UserRequest::MintPrincipalSession {
            user_id: user_id.to_string(),
            evidence: kotton_wire::ipc::PrincipalEvidence::VerifiedPeerKey {
                pubkey_hex: pubkey_hex.to_string(),
            },
        })
        .await?
    {
        UserResponse::PrincipalSession { token } => Ok(token.expose().to_owned()),
        UserResponse::NotAllowed => Err(io::Error::other("peer is not an authorised client")),
        other => Err(io::Error::other(format!("unexpected mint response: {other:?}"))),
    }
}

// ---------------------------------------------------------------------------
// Per-connection handler
// ---------------------------------------------------------------------------

/// The peer's Ed25519 public key on this connection, hex-encoded, read from the
/// certificate the TLS handshake verified.
///
/// `PairedDeviceVerifier` already established that this certificate is in the
/// allowlist; this recovers *whose* it is, which the gateway hands to kuserd as
/// evidence (RFC-0043). Before this, the identity was verified and then thrown
/// away — which is what made the gateway a confused deputy.
///
/// Deliberately the raw key rather than a derived DID: the gateway reports what
/// it saw and kuserd draws the conclusion.
fn peer_pubkey_of(conn: &quinn::Connection) -> Option<String> {
    let identity = conn.peer_identity()?;
    let certs = identity
        .downcast::<Vec<rustls::pki_types::CertificateDer<'static>>>()
        .ok()?;
    let leaf = certs.first()?;
    Some(hex::encode(extract_ed25519_pubkey_from_cert(leaf)?))
}

/// Accept all bidirectional streams on a single QUIC connection.
///
/// `PairedDeviceVerifier` already enforced that the remote certificate is in
/// the allowlist during the TLS handshake. This mints a session **for that peer**
/// (RFC-0043) and proxies its streams under that session, so kuserd sees the
/// peer rather than the gateway. The bootstrap token is used only to mint.
async fn handle_connection(
    conn: quinn::Connection,
    bootstrap_token: String,
    ipc_endpoint: IpcEndpoint,
    user_id: String,
) {
    let Some(pubkey_hex) = peer_pubkey_of(&conn) else {
        tracing::warn!("kquicd: could not recover the peer key; refusing the connection");
        return;
    };

    let principal_token =
        match mint_principal_session(&ipc_endpoint, &bootstrap_token, &user_id, &pubkey_hex).await
        {
            Ok(t) => t,
            Err(e) => {
                tracing::warn!(
                    %pubkey_hex, error = %e,
                    "kquicd: kuserd refused to mint a session for this peer"
                );
                return;
            }
        };

    loop {
        match conn.accept_bi().await {
            Ok((send, recv)) => {
                let token = principal_token.clone();
                let ep = ipc_endpoint.clone();
                tokio::spawn(handle_stream(send, recv, token, ep));
            }
            Err(e) => {
                tracing::debug!(error = %e, "kquicd: connection closed");
                return;
            }
        }
    }
}

/// Handle a single request–response round-trip on a bidirectional QUIC stream.
///
/// Frame format (same as `QuicConnection`): 4-byte big-endian u32 length, then
/// JSON bytes.
async fn handle_stream(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    bootstrap_token: String,
    ipc_endpoint: IpcEndpoint,
) {
    if let Err(e) = do_stream(&mut send, &mut recv, &bootstrap_token, &ipc_endpoint).await {
        tracing::warn!(error = %e, "kquicd: stream error");
        // Best-effort error frame back to the remote client.
        let _ = write_response_frame(
            &mut send,
            &UserResponse::Error {
                message: e.to_string(),
            },
        )
        .await;
    }
}

async fn do_stream(
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
    bootstrap_token: &str,
    ipc_endpoint: &IpcEndpoint,
) -> io::Result<()> {
    // 1. Read length-prefixed frame.
    let len = recv.read_u32().await.map_err(io::Error::other)?;
    if len > MAX_FRAME_BYTES {
        return Err(io::Error::other(format!(
            "incoming frame too large: {len} bytes (max {MAX_FRAME_BYTES})"
        )));
    }
    let mut buf = vec![0u8; len as usize];
    recv.read_exact(&mut buf)
        .await
        .map_err(io::Error::other)?;

    // 2. Parse `RemoteRequest` — treat all parse errors as protocol violations.
    //    A gateway stream is a `Remote` caller, so a `Local`-tier operation is not
    //    something a peer can name: it fails here, as a malformed frame, rather
    //    than being decoded and then refused (RFC-0082).
    let request: RemoteRequest = match serde_json::from_slice(&buf) {
        Ok(r) => r,
        Err(e) => {
            let resp = UserResponse::Error {
                message: format!("invalid request: {e}"),
            };
            return write_response_frame(send, &resp).await;
        }
    };

    // 3. The trust floor used to be enforced here. Nothing is left to enforce:
    //    step 2 cannot produce a Local-tier variant. kuserd still applies the floor
    //    authoritatively on its own socket.
    let request: UserRequest = request.into();

    // 4. Open a fresh IPC connection for this stream and forward the request.
    let mut ipc = IpcClient::<UserRequest, UserResponse>::connect(ipc_endpoint.clone())
        .await
        .map_err(|e| io::Error::other(format!("IPC connect failed: {e}")))?;

    // Authenticate with no scope restriction — kquicd already enforces
    // the trust floor and the bootstrap token is trusted.
    match ipc
        .send(&UserRequest::Authenticate {
            token: kotton_wire::ipc::SecretText::new(bootstrap_token.to_string()),
            scope: None,
        })
        .await?
    {
        UserResponse::ActiveSession { .. } => {}
        _ => {
            return Err(io::Error::other("per-stream IPC auth failed"));
        }
    }

    let response = ipc
        .send(&request)
        .await
        .unwrap_or_else(|e| UserResponse::Error {
            message: format!("IPC error: {e}"),
        });

    write_response_frame(send, &response).await
}

/// Write a length-prefixed JSON response frame (4-byte big-endian u32 length).
async fn write_response_frame(
    send: &mut quinn::SendStream,
    response: &UserResponse,
) -> io::Result<()> {
    let json =
        serde_json::to_vec(response).map_err(|e| io::Error::other(format!("serialize: {e}")))?;
    let len = json.len() as u32;
    send.write_u32(len).await.map_err(io::Error::other)?;
    send.write_all(&json).await.map_err(io::Error::other)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Fetch the raw Ed25519 public-key bytes for all paired clients of `user_id`.
async fn fetch_allowed_keys(
    client: &mut IpcClient<UserRequest, UserResponse>,
    user_id: &str,
) -> io::Result<HashSet<[u8; 32]>> {
    match client
        .send(&UserRequest::GetAuthorizedClients {
            user_id: user_id.to_string(),
        })
        .await?
    {
        UserResponse::AuthorizedClients { pubkey_hexes, .. } => {
            let mut set = HashSet::with_capacity(pubkey_hexes.len());
            for hex_str in pubkey_hexes {
                let bytes = hex::decode(&hex_str)
                    .map_err(|e| io::Error::other(format!("bad pubkey hex: {e}")))?;
                let arr: [u8; 32] = bytes
                    .try_into()
                    .map_err(|_| io::Error::other("pubkey must be 32 bytes"))?;
                set.insert(arr);
            }
            Ok(set)
        }
        other => Err(io::Error::other(format!(
            "GetAuthorizedClients unexpected: {other:?}"
        ))),
    }
}

/// Open a fresh IPC connection and re-fetch the allowed-key set.
async fn refresh_allowed_keys(
    token: &str,
    ipc_endpoint: &IpcEndpoint,
    user_id: &str,
) -> io::Result<HashSet<[u8; 32]>> {
    let mut client: IpcClient<UserRequest, UserResponse> =
        IpcClient::connect(ipc_endpoint.clone()).await?;
    client
        .send(&UserRequest::Authenticate {
            token: kotton_wire::ipc::SecretText::new(token.to_string()),
            scope: Some(vec!["GetAuthorizedClients".to_string()]),
        })
        .await?;
    fetch_allowed_keys(&mut client, user_id).await
}

/// Build the IPC endpoint for the local kuserd instance.
fn build_ipc_endpoint() -> io::Result<IpcEndpoint> {
    let name = kuserd_ipc_name();

    #[cfg(windows)]
    {
        Ok(IpcEndpoint::NamedPipe(name))
    }

    #[cfg(unix)]
    {
        // The socket the supervisor bound, or a bare name resolved the daemon's
        // way — never a path handed to the name resolver (kotton_common).
        let _ = &name;
        let path = kotton_common::kuserd_socket_from_env().map_err(|e| io::Error::other(e.to_string()))?;
        Ok(IpcEndpoint::UnixSocket(path))
    }
}
