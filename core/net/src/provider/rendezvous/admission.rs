// SPDX-License-Identifier: AGPL-3.0-or-later
//! The admission tag a device presents at a relay, and the operator's two
//! requests to it
//! (`TASK-a-device-presents-its-relays-admission-tag-and-the-reach-row-sets-the-rule`).
//!
//! **The tag** is HMAC-SHA256, under a relay's admission key, over
//! [`admission_tag_input`] — the handle's fingerprint and the timestamp its own
//! signature covers — sent as `admit=` in the handle's `Authorization` header or
//! as `admission` in a push. It changes with every request because the
//! timestamp does, and it is made under a key every member of the set holds
//! alike, so a relay reading two tags learns that both callers hold the key and
//! nothing that joins the two: no tag is a durable name for anyone.
//!
//! **The operator's requests** go to `POST /operator`, signed by the relay's
//! operator credential over [`operator_signing_input`] of the body's exact
//! bytes. The key is the credential's own; this file holds it only for the
//! length of a call.

use std::sync::atomic::{AtomicI64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signer, SigningKey};
use hmac::{Hmac, Mac};
use kotton_wire::rendezvous::{
    admission_tag_input, operator_signing_input, RelayOperatorRequest, RelayOperatorResponse,
    RendezvousErrorResponse,
};
use sha2::Sha256;

use super::client::RendezvousError;

/// One relay admission key: 32 bytes a set of people hold alike. Prints as
/// `<redacted>`; the bytes leave only as a tag, as the base64url a sealed
/// channel hands on ([`Self::to_text`]), or — the *invited* key alone — inside
/// the invite an operator hands a person ([`Self::to_bytes`]).
#[derive(Clone, PartialEq, Eq)]
pub struct AdmissionKey([u8; 32]);

impl std::fmt::Debug for AdmissionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AdmissionKey(<redacted>)")
    }
}

impl AdmissionKey {
    /// A fresh key from the OS's randomness.
    pub fn generate() -> Self {
        use rand::RngCore as _;
        let mut k = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut k);
        Self(k)
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Read a key as the wire carries it: 32 bytes, base64url without padding.
    pub fn parse(text: &str) -> Option<Self> {
        let bytes = URL_SAFE_NO_PAD.decode(text.trim()).ok()?;
        Some(Self(bytes.try_into().ok()?))
    }

    /// The key as the wire carries it, for the sealed channels that hand it on
    /// and nothing else.
    pub fn to_text(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.0)
    }

    /// The key's 32 bytes, for the one code that carries it to a person: a
    /// relay's invite (`kotton_wire::line::InviteCode::Relay`), which its
    /// operator mints from the *invited* key they keep and nothing else.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }

    /// The tag for a request whose handle `fingerprint` signed `ts`.
    pub fn tag(&self, fingerprint: &str, ts: i64) -> String {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&self.0).expect("HMAC takes any key length");
        mac.update(&admission_tag_input(fingerprint, ts));
        URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    }
}

/// The last timestamp an operator request from this process was signed at.
/// The relay refuses a set no newer than the last one it took (its replay
/// guard), and its clock counts seconds, so two sets inside one second would
/// have the second refused: each request is signed at least one second after
/// the one before it. The relay allows thirty seconds of skew, far more than
/// any run of requests here spends.
static LAST_SIGNED: AtomicI64 = AtomicI64::new(0);

fn next_ts() -> Result<i64, RendezvousError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .map_err(|e| RendezvousError::Clock(e.to_string()))?;
    let mut prev = LAST_SIGNED.load(Ordering::SeqCst);
    loop {
        let ts = now.max(prev + 1);
        match LAST_SIGNED.compare_exchange(prev, ts, Ordering::SeqCst, Ordering::SeqCst) {
            Ok(_) => return Ok(ts),
            Err(p) => prev = p,
        }
    }
}

/// Say `request` to the relay at `relay_url` as its operator `key`, and read
/// its answer. A relay that refuses the key, or does not answer, is an error;
/// a request it read and could not do is its `Refused` answer.
pub async fn say_as_operator(
    relay_url: &str,
    key: &SigningKey,
    request: &RelayOperatorRequest,
) -> Result<RelayOperatorResponse, RendezvousError> {
    let body = serde_json::to_vec(request).expect("an operator request serialises");
    let key_hex = hex::encode(key.verifying_key().to_bytes());
    let ts = next_ts()?;
    let sig = URL_SAFE_NO_PAD.encode(key.sign(&operator_signing_input(&key_hex, ts, &body)).to_bytes());
    let resp = reqwest::Client::new()
        .post(format!("{}/operator", relay_url.trim_end_matches('/')))
        .header("Authorization", format!("KottonOperator key={key_hex} ts={ts} sig={sig}"))
        .header("Content-Type", "application/json")
        .body(body)
        .send()
        .await?;
    let status = resp.status();
    if !status.is_success() {
        let err: RendezvousErrorResponse = resp.json().await.unwrap_or(RendezvousErrorResponse {
            error: "(no body)".to_owned(),
        });
        return Err(RendezvousError::HttpError {
            status: status.as_u16(),
            body: err.error,
        });
    }
    Ok(resp.json().await?)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The tag is the relay's own computation: HMAC-SHA256 under the key over
    /// `admission_tag_input`, base64url. Two requests by one handle carry
    /// different tags, and the key never prints.
    #[test]
    fn a_tag_is_the_mac_the_relay_checks_and_changes_every_request() {
        let key = AdmissionKey::from_bytes([9u8; 32]);
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&[9u8; 32]).unwrap();
        mac.update(b"kotton-relay-admission-v1\ndid:key:zH\n7");
        assert_eq!(key.tag("did:key:zH", 7), URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes()));
        assert_ne!(key.tag("did:key:zH", 7), key.tag("did:key:zH", 8));
        assert_eq!(AdmissionKey::parse(&key.to_text()), Some(key.clone()));
        assert!(!format!("{key:?}").contains(&key.to_text()));
        assert_eq!(AdmissionKey::parse("short"), None);
    }

    /// Requests signed in one second are signed a second apart, so the relay's
    /// replay guard never refuses a set for coming too soon after another.
    #[test]
    fn each_operator_request_is_signed_after_the_last() {
        let a = next_ts().unwrap();
        let b = next_ts().unwrap();
        assert!(b > a);
    }
}
