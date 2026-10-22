// SPDX-License-Identifier: AGPL-3.0-or-later
//! Ask a relay for its key (`TASK-a-relay-has-a-key-of-its-own-and-proves-it`).
//!
//! The transport half only: one `GET /identity?nonce=<hex>` and its body. What
//! the answer is believed for — whether the signature holds, whether the key is
//! the one expected — is `kotton_peer::relay_key`, which is where a device
//! decides what a relay is.

use kotton_wire::rendezvous::{RelayIdentity, RendezvousErrorResponse};

use super::RendezvousError;

/// Dial `relay_url` and ask it to sign `nonce`. `Ok(None)` is a relay that
/// answered and keeps no key (`404` — one started without a state directory, or
/// one from before relays had keys); every other refusal is an error.
pub async fn fetch_relay_identity(
    relay_url: &str,
    nonce: &[u8],
    timeout: std::time::Duration,
) -> Result<Option<RelayIdentity>, RendezvousError> {
    let nonce_hex = hex::encode(nonce);
    let resp = reqwest::Client::builder()
        .timeout(timeout)
        .build()?
        .get(format!("{}/identity?nonce={nonce_hex}", relay_url.trim().trim_end_matches('/')))
        .send()
        .await?;
    let status = resp.status();
    if status == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    if !status.is_success() {
        let err: RendezvousErrorResponse = resp.json().await.unwrap_or(RendezvousErrorResponse {
            error: "(no body)".to_owned(),
        });
        return Err(RendezvousError::HttpError {
            status: status.as_u16(),
            body: err.error,
        });
    }
    Ok(Some(resp.json().await?))
}
