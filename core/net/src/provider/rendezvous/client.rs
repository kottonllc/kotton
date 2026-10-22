// SPDX-License-Identifier: AGPL-3.0-or-later
//! HTTP client for the `kotton-rendezvous` peer-address exchange service.
//!
//! Handles signing push payloads with the device's Ed25519 identity key and
//! issuing authenticated lookup requests. All network I/O is async (tokio).

use std::net::SocketAddr;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signer, SigningKey};
use kotton_wire::rendezvous::{
    RendezvousErrorResponse, RendezvousLookupResponse, RendezvousPushPayload,
    RendezvousPushResponse,
};
use reqwest::Client;

/// Errors produced by the rendezvous client.
#[derive(Debug, thiserror::Error)]
pub enum RendezvousError {
    #[error("HTTP error from rendezvous server: {status} \u{2014} {body}")]
    HttpError { status: u16, body: String },

    #[error("Request error: {0}")]
    Request(#[from] reqwest::Error),

    #[error("No entry found for fingerprint {0}")]
    NotFound(String),

    #[error("Invalid address returned by rendezvous server: {0}")]
    InvalidAddr(String),

    #[error("Clock error: {0}")]
    Clock(String),
}

/// A signed client that interacts with a `kotton-rendezvous` endpoint.
///
/// Construct once and reuse across push/lookup calls; the inner `reqwest::Client`
/// maintains a connection pool.
pub struct RendezvousClient {
    http: Client,
    base_url: String,
    fingerprint: String,
    signing_key: SigningKey,
    /// The relay's admission key this device holds, if any: every push and
    /// lookup carries a tag under it, which a relay whose rule is narrowed
    /// reads and a relay admitting anyone ignores.
    admission: Option<super::AdmissionKey>,
}

impl RendezvousClient {
    /// Create a new client.
    ///
    /// - `base_url`: e.g. `"https://coord.kotton.dev"` (no trailing slash)
    /// - `fingerprint`: DID key fingerprint of this device, e.g. `"did:key:z6Mk..."`
    /// - `signing_key`: the device's Ed25519 signing key (private half)
    pub fn new(
        base_url: impl Into<String>,
        fingerprint: impl Into<String>,
        signing_key: SigningKey,
    ) -> Self {
        Self {
            http: Client::new(),
            base_url: base_url.into().trim_end_matches('/').to_owned(),
            fingerprint: fingerprint.into(),
            signing_key,
            admission: None,
        }
    }

    /// Present a tag under `key` on every request from here on.
    pub fn with_admission(mut self, key: Option<super::AdmissionKey>) -> Self {
        self.admission = key;
        self
    }

    /// Register this device's external address with the coord server.
    ///
    /// `turn_relay_addr` is the TURN relay address allocated for this device,
    /// if any. Pass `None` during the initial STUN/hole-punch phase.
    ///
    /// Returns the TTL (in seconds) the server will hold the entry for.
    pub async fn push(
        &self,
        external_addr: SocketAddr,
        turn_relay_addr: Option<SocketAddr>,
        relayable: bool,
    ) -> Result<u32, RendezvousError> {
        let addr_str = external_addr.to_string();
        let relay_str = turn_relay_addr.map(|a| a.to_string());
        let timestamp = unix_now()?;

        // Sign: "{fingerprint}\n{addr}\n{timestamp}\n{turn_relay_or_empty}\n{relayable}"
        let relay_for_sig = relay_str.as_deref().unwrap_or("");
        let payload_to_sign = format!(
            "{}\n{}\n{}\n{}\n{}",
            self.fingerprint, addr_str, timestamp, relay_for_sig, relayable
        );
        let sig_bytes = self.signing_key.sign(payload_to_sign.as_bytes());
        let sig = URL_SAFE_NO_PAD.encode(sig_bytes.to_bytes());

        let body = RendezvousPushPayload {
            fingerprint: self.fingerprint.clone(),
            addr: addr_str,
            timestamp,
            sig,
            turn_relay_addr: relay_str,
            relayable,
            admission: self.admission.as_ref().map(|k| k.tag(&self.fingerprint, timestamp)),
        };

        let resp = self
            .http
            .post(format!("{}/push", self.base_url))
            .json(&body)
            .send()
            .await?;

        let status = resp.status();
        if status.is_success() {
            let push_resp: RendezvousPushResponse = resp.json().await?;
            Ok(push_resp.expires_in)
        } else {
            let code = status.as_u16();
            let err: RendezvousErrorResponse =
                resp.json().await.unwrap_or(RendezvousErrorResponse {
                    error: "(no body)".to_owned(),
                });
            Err(RendezvousError::HttpError {
                status: code,
                body: err.error,
            })
        }
    }

    /// Look up the external address of a peer device by its fingerprint.
    ///
    /// Returns `(reflexive_addr, turn_relay_addr)`. `turn_relay_addr` is `None`
    /// when the peer has not pushed a relay address yet.
    ///
    /// Returns `Err(RendezvousError::NotFound)` when the peer has no live entry.
    pub async fn lookup(
        &self,
        peer_fingerprint: &str,
    ) -> Result<(SocketAddr, Option<SocketAddr>), RendezvousError> {
        let timestamp = unix_now()?;
        // Authorization header: "Ed25519 fingerprint=<fp> ts=<ts> sig=<sig>"
        let auth_payload = format!("{}\n{}", self.fingerprint, timestamp);
        let auth_sig =
            URL_SAFE_NO_PAD.encode(self.signing_key.sign(auth_payload.as_bytes()).to_bytes());
        let mut auth_value = format!(
            "Ed25519 fingerprint={} ts={} sig={}",
            self.fingerprint, timestamp, auth_sig
        );
        if let Some(k) = &self.admission {
            auth_value.push_str(&format!(" admit={}", k.tag(&self.fingerprint, timestamp)));
        }

        let resp = self
            .http
            .get(format!("{}/lookup/{}", self.base_url, peer_fingerprint))
            .header("Authorization", auth_value)
            .send()
            .await?;

        let status = resp.status();
        if status.as_u16() == 404 {
            return Err(RendezvousError::NotFound(peer_fingerprint.to_owned()));
        }
        if !status.is_success() {
            let code = status.as_u16();
            let err: RendezvousErrorResponse =
                resp.json().await.unwrap_or(RendezvousErrorResponse {
                    error: "(no body)".to_owned(),
                });
            return Err(RendezvousError::HttpError {
                status: code,
                body: err.error,
            });
        }

        let lookup: RendezvousLookupResponse = resp.json().await?;
        let addr = SocketAddr::from_str(&lookup.addr)
            .map_err(|_| RendezvousError::InvalidAddr(lookup.addr.clone()))?;
        let relay = lookup
            .turn_relay_addr
            .map(|s| SocketAddr::from_str(&s).map_err(|_| RendezvousError::InvalidAddr(s)))
            .transpose()?;
        Ok((addr, relay))
    }

    /// Ping the coord server's `/healthz` endpoint.
    ///
    /// Returns `true` if the server is reachable and returns 200.
    pub async fn healthcheck(&self) -> bool {
        match self
            .http
            .get(format!("{}/healthz", self.base_url))
            .send()
            .await
        {
            Ok(r) => r.status().is_success(),
            Err(_) => false,
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn unix_now() -> Result<i64, RendezvousError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .map_err(|e| RendezvousError::Clock(e.to_string()))
}
