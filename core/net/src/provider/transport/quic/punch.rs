// SPDX-License-Identifier: AGPL-3.0-or-later
//! Simultaneous QUIC hole-punch for NAT traversal (RFC 5128 §3.4).
//!
//! # Protocol
//!
//! 1. Both peers discover their public address via STUN and exchange it through
//!    the coord server.
//! 2. Role is determined deterministically: the peer with the lexicographically
//!    *smaller* Ed25519 public key becomes the **Initiator** (connects), the
//!    other becomes the **Responder** (accepts).
//! 3. Both bind a UDP socket to the local STUN port and send a few probe packets
//!    to the peer's STUN address.  This opens an inbound hole in symmetric/full-
//!    cone NATs on both sides before the QUIC handshake begins.
//! 4. Initiator calls `quinn::Endpoint::connect()`, Responder calls
//!    `quinn::Endpoint::accept()`, both within a configurable timeout.
//! 5. If no connection is established before the timeout, the caller should
//!    fall back to TURN relay (see `crates/05_runtime/src/device/network/nat.rs`).

use std::{
    collections::HashSet,
    net::SocketAddr,
    sync::{Arc, RwLock},
    time::Duration,
};

use quinn::Endpoint;
use thiserror::Error;
use tracing::{debug, warn};

use super::tls::{self, Ed25519DeviceCert, PairedDeviceVerifier};

// ── Constants ────────────────────────────────────────────────────────────────

/// Default hole-punch deadline.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

/// Number of UDP probe packets and gap between them.
const PROBE_COUNT: usize = 3;
const PROBE_INTERVAL: Duration = Duration::from_millis(50);

/// Dummy SNI hostname (peer TLS verification is done by raw public-key, not hostname).
const PEER_SNI: &str = "kotton-peer";

// ── Role ─────────────────────────────────────────────────────────────────────

/// Which side of the hole-punch this device takes.
///
/// Determined by comparing the local and peer Ed25519 public keys lexicographically.
/// The side with the smaller key always connects (Initiator); the other accepts
/// (Responder).  This ensures both sides agree on roles without any negotiation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PunchRole {
    /// This device's public key is lexicographically smaller — it connects.
    Initiator,
    /// This device's public key is lexicographically larger — it accepts.
    Responder,
}

impl PunchRole {
    /// Compute role from the two 32-byte Ed25519 public keys.
    ///
    /// The side whose public key is lexicographically *smaller* becomes the
    /// Initiator (connects). If both keys are equal the local side is Responder.
    pub fn determine(local_pubkey: &[u8; 32], peer_pubkey: &[u8; 32]) -> Self {
        if local_pubkey < peer_pubkey {
            PunchRole::Initiator
        } else {
            PunchRole::Responder
        }
    }
}

// ── Error / Result ───────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum PunchError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("TLS configuration error: {0}")]
    Tls(String),

    #[error("QUIC error: {0}")]
    Quic(String),
}

/// Outcome of a [`simultaneous_punch`] attempt.
#[derive(Debug)]
pub enum PunchResult {
    /// Hole-punch succeeded; the `quinn::Connection` is ready to use.
    Direct(quinn::Connection),
    /// Timed out — no direct path could be established; fall back to TURN relay.
    NeedsTurn,
    /// A hard error occurred (misconfig, TLS rejection, etc.).
    Failed(PunchError),
}

// ── Public API ───────────────────────────────────────────────────────────────

/// Attempt a simultaneous QUIC hole-punch to `peer_addr`.
///
/// # Arguments
///
/// - `device_key` — local device's Ed25519 signing key (for mTLS cert).
/// - `local_bind` — local `host:port` to bind on.  **Must** be the port that
///   the STUN server reflected back (so the NAT maps inbound traffic to it).
/// - `peer_addr` — the peer's STUN-observed public address.
/// - `peer_pubkey` — peer's 32-byte Ed25519 public key (allowlist verification).
/// - `role` — see [`PunchRole`].  Compute with [`PunchRole::determine`].
/// - `timeout` — maximum wait.  Pass `None` for the 5-second default.
/// - `keepalive` — QUIC keep-alive interval.  Pass `None` to use quinn default
///   (no periodic keep-alive).  Set to e.g. `Some(Duration::from_secs(20))`
///   for NAT-binding keepalive pings.
///
/// Returns [`PunchResult::Direct`] on success, [`PunchResult::NeedsTurn`] on
/// timeout, or [`PunchResult::Failed`] for non-recoverable errors.
#[allow(clippy::too_many_arguments)]
pub async fn simultaneous_punch(
    device_key: &ed25519_dalek::SigningKey,
    offer: &tls::CertOffer,
    local_bind: SocketAddr,
    peer_addr: SocketAddr,
    peer_pubkey: [u8; 32],
    role: PunchRole,
    timeout: Option<Duration>,
    keepalive: Option<Duration>,
) -> PunchResult {
    let timeout = timeout.unwrap_or(DEFAULT_TIMEOUT);

    match punch_inner(
        device_key,
        offer,
        local_bind,
        peer_addr,
        peer_pubkey,
        role,
        timeout,
        keepalive,
    )
    .await
    {
        Ok(conn) => PunchResult::Direct(conn),
        Err(PunchInnerError::Timeout) => {
            debug!(
                peer = %peer_addr, ?role,
                "hole-punch timed out after {:.1}s",
                timeout.as_secs_f32()
            );
            PunchResult::NeedsTurn
        }
        Err(PunchInnerError::Punch(e)) => PunchResult::Failed(e),
    }
}

// ── Internals ────────────────────────────────────────────────────────────────

#[derive(Debug)]
enum PunchInnerError {
    Timeout,
    Punch(PunchError),
}

impl From<PunchError> for PunchInnerError {
    fn from(e: PunchError) -> Self {
        PunchInnerError::Punch(e)
    }
}

#[allow(clippy::too_many_arguments)]
async fn punch_inner(
    device_key: &ed25519_dalek::SigningKey,
    offer: &tls::CertOffer,
    local_bind: SocketAddr,
    peer_addr: SocketAddr,
    peer_pubkey: [u8; 32],
    role: PunchRole,
    timeout: Duration,
    keepalive: Option<Duration>,
) -> Result<quinn::Connection, PunchInnerError> {
    // ── 1. Build mTLS configs ────────────────────────────────────────────────
    let paired = {
        let mut set = HashSet::new();
        set.insert(peer_pubkey);
        Arc::new(RwLock::new(set))
    };
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let device_cert = Ed25519DeviceCert::from_signing_key_with_offer(device_key, offer)
        .map_err(|e| PunchError::Tls(e.to_string()))?;
    let verifier = PairedDeviceVerifier::new(Arc::clone(&paired), Arc::clone(&provider));
    let verifier = Arc::new(verifier);

    let server_cfg = tls::build_peer_server_config(
        &device_cert,
        Arc::clone(&verifier),
        Arc::clone(&provider),
        keepalive,
    )
    .map_err(|e| PunchError::Tls(e.to_string()))?;

    let client_cfg = tls::build_peer_client_config(
        &device_cert,
        Arc::clone(&verifier),
        Arc::clone(&provider),
        keepalive,
    )
    .map_err(|e| PunchError::Tls(e.to_string()))?;

    // ── 2. Bind UDP socket and send hole-punch probes ────────────────────────
    // We use a tokio UdpSocket so we can send async probes, then convert it
    // to a std socket for quinn::Endpoint::new().
    let udp = tokio::net::UdpSocket::bind(local_bind)
        .await
        .map_err(PunchError::Io)?;

    debug!(?role, local = %local_bind, peer = %peer_addr, "sending hole-punch probes");
    // Best-effort: failures are ignored (probe loss is normal under NAT).
    for i in 0..PROBE_COUNT {
        let _ = udp.send_to(&[0u8; 4], peer_addr).await;
        if i + 1 < PROBE_COUNT {
            tokio::time::sleep(PROBE_INTERVAL).await;
        }
    }
    debug!(?role, "probes sent; establishing QUIC endpoint");

    // Convert to std socket (quinn needs a non-blocking std::UdpSocket).
    let std_sock = udp.into_std().map_err(PunchError::Io)?;
    std_sock.set_nonblocking(true).map_err(PunchError::Io)?;

    // ── 3. Build quinn Endpoint from the pre-bound socket ───────────────────
    let server_cfg_opt = match role {
        PunchRole::Responder => Some(server_cfg),
        PunchRole::Initiator => None, // initiator only connects; no need to accept
    };

    let endpoint = Endpoint::new(
        quinn::EndpointConfig::default(),
        server_cfg_opt,
        std_sock,
        Arc::new(quinn::TokioRuntime),
    )
    .map_err(|e| PunchError::Quic(e.to_string()))?;

    // ── 4. Connect or accept, race against timeout ───────────────────────────
    let conn_fut = async {
        match role {
            PunchRole::Initiator => {
                let conn = endpoint
                    .connect_with(client_cfg, peer_addr, PEER_SNI)
                    .map_err(|e| PunchError::Quic(e.to_string()))?
                    .await
                    .map_err(|e| PunchError::Quic(e.to_string()))?;
                debug!(peer = %peer_addr, "hole-punch succeeded (initiator)");
                Ok::<quinn::Connection, PunchError>(conn)
            }
            PunchRole::Responder => {
                let incoming = endpoint
                    .accept()
                    .await
                    .ok_or_else(|| PunchError::Quic("endpoint closed".into()))?;
                // Also connect outward so we confirm the peer is the expected one.
                // (The mTLS verifier will reject any unexpected connections.)
                let conn = incoming
                    .accept()
                    .map_err(|e| PunchError::Quic(e.to_string()))?
                    .await
                    .map_err(|e| PunchError::Quic(e.to_string()))?;
                debug!(peer = %peer_addr, "hole-punch succeeded (responder)");
                Ok::<quinn::Connection, PunchError>(conn)
            }
        }
    };

    match tokio::time::timeout(timeout, conn_fut).await {
        Ok(Ok(conn)) => Ok(conn),
        Ok(Err(e)) => Err(PunchInnerError::Punch(e)),
        Err(_elapsed) => {
            // Close the endpoint gracefully before returning NeedsTurn.
            endpoint.close(0u32.into(), b"punch-timeout");
            warn!(?role, peer = %peer_addr, "hole-punch timeout");
            Err(PunchInnerError::Timeout)
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn make_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    #[test]
    fn role_determination_is_deterministic() {
        let a = make_key(0x01).verifying_key().to_bytes();
        let b = make_key(0x02).verifying_key().to_bytes();

        // Whichever key is smaller, that side is Initiator; the other is Responder.
        let (smaller, larger) = if a < b { (&a, &b) } else { (&b, &a) };
        assert_eq!(PunchRole::determine(smaller, larger), PunchRole::Initiator);
        assert_eq!(PunchRole::determine(larger, smaller), PunchRole::Responder);

        // Equal keys: not less-than → Responder
        assert_eq!(PunchRole::determine(&a, &a), PunchRole::Responder);
    }

    #[test]
    fn role_is_opposite_on_both_sides() {
        let a = make_key(0x10).verifying_key().to_bytes();
        let b = make_key(0x20).verifying_key().to_bytes();
        assert_ne!(PunchRole::determine(&a, &b), PunchRole::determine(&b, &a));
    }
}
