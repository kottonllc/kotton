// SPDX-License-Identifier: AGPL-3.0-or-later
//! Ed25519 payload authentication for the coord server.
//!
//! Verifies push payloads and lookup `Authorization` headers.
//!
//! ## did:key → Ed25519 public key
//!
//! A `did:key:z6Mk...` fingerprint encodes an Ed25519 public key as follows:
//!
//! 1. Strip the `did:key:` prefix.
//! 2. The remaining string starts with `z` — the multibase base58btc indicator.
//! 3. Strip the `z`, base58-decode the rest.
//! 4. The decoded bytes start with the varint multicodec for Ed25519 (`0xed 0x01`).
//! 5. The following 32 bytes are the raw Ed25519 public key.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::{Signature, VerifyingKey};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tracing::warn;

/// Maximum clock skew (seconds) tolerated between client and server.
const MAX_CLOCK_SKEW: i64 = 30;

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("Fingerprint is not a did:key: '{0}'")]
    NotDidKey(String),

    #[error("Failed to base58-decode did:key identifier: {0}")]
    Base58Decode(String),

    #[error("Multicodec prefix is not Ed25519 (0xed 0x01); got 0x{0:02x} 0x{1:02x}")]
    WrongCodec(u8, u8),

    #[error("Decoded key is {0} bytes; expected 32")]
    WrongKeyLength(usize),

    #[error("Invalid Ed25519 public key: {0}")]
    InvalidKey(String),

    #[error("Timestamp {ts} rejected: clock skew {skew}s exceeds limit {limit}s")]
    ClockSkew { ts: i64, skew: i64, limit: i64 },

    #[error("Base64 signature decode failed: {0}")]
    SigDecode(String),

    #[error("Signature verification failed")]
    BadSignature,

    #[error("Malformed Authorization header")]
    MalformedAuth,
}

/// Extract a 32-byte Ed25519 public key from a `did:key:z6Mk...` fingerprint.
pub fn ed25519_key_from_did(fingerprint: &str) -> Result<VerifyingKey, AuthError> {
    // 1. Strip `did:key:` prefix
    let identifier = fingerprint
        .strip_prefix("did:key:")
        .ok_or_else(|| AuthError::NotDidKey(fingerprint.to_owned()))?;

    // 2. Strip `z` multibase prefix (base58btc)
    let b58 = identifier
        .strip_prefix('z')
        .ok_or_else(|| AuthError::NotDidKey(fingerprint.to_owned()))?;

    // 3. Base58 decode
    let decoded = bs58::decode(b58)
        .into_vec()
        .map_err(|e| AuthError::Base58Decode(e.to_string()))?;

    // 4. Verify multicodec prefix: Ed25519 = 0xed 0x01
    if decoded.len() < 2 {
        return Err(AuthError::WrongKeyLength(decoded.len()));
    }
    if decoded[0] != 0xed || decoded[1] != 0x01 {
        return Err(AuthError::WrongCodec(decoded[0], decoded[1]));
    }

    // 5. Extract the 32-byte key
    let key_bytes = &decoded[2..];
    if key_bytes.len() != 32 {
        return Err(AuthError::WrongKeyLength(key_bytes.len()));
    }

    let arr: [u8; 32] = key_bytes
        .try_into()
        .map_err(|_| AuthError::WrongKeyLength(key_bytes.len()))?;

    VerifyingKey::from_bytes(&arr).map_err(|e| AuthError::InvalidKey(e.to_string()))
}

/// Verify the timestamp from a push payload is within the allowed clock skew.
pub fn verify_timestamp(timestamp: i64) -> Result<(), AuthError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    let skew = (now - timestamp).abs();
    if skew > MAX_CLOCK_SKEW {
        warn!(timestamp, now, skew, "relay push rejected: clock skew");
        return Err(AuthError::ClockSkew {
            ts: timestamp,
            skew,
            limit: MAX_CLOCK_SKEW,
        });
    }
    Ok(())
}

/// Verify the Ed25519 signature over a push payload.
///
/// The signed message is:
/// `"{fingerprint}\n{addr}\n{timestamp}\n{turn_relay_addr_or_empty}\n{relayable}"`
/// (no trailing newline). If no relay address was included `turn_relay_addr` is
/// `None` and the fourth line is an empty string; the fifth line is `"true"` or
/// `"false"`. This matches the signing procedure in `rendezvous/client.rs`.
pub fn verify_push_sig(
    verifying_key: &VerifyingKey,
    fingerprint: &str,
    addr: &str,
    timestamp: i64,
    turn_relay_addr: Option<&str>,
    relayable: bool,
    sig_b64: &str,
) -> Result<(), AuthError> {
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(sig_b64)
        .map_err(|e| AuthError::SigDecode(e.to_string()))?;

    let sig_arr: [u8; 64] = sig_bytes
        .as_slice()
        .try_into()
        .map_err(|_| AuthError::SigDecode(format!("expected 64 bytes, got {}", sig_bytes.len())))?;

    let signature = Signature::from_bytes(&sig_arr);
    let relay = turn_relay_addr.unwrap_or("");
    let message = format!(
        "{}\n{}\n{}\n{}\n{}",
        fingerprint, addr, timestamp, relay, relayable
    );

    use ed25519_dalek::Verifier as _;
    verifying_key
        .verify(message.as_bytes(), &signature)
        .map_err(|_| AuthError::BadSignature)
}

/// A handle that proved itself: its fingerprint, the timestamp it signed, and the
/// admission tag it carried beside the signature, if any (`admit=`), which the
/// relay's rule reads next.
#[derive(Debug)]
pub struct Handle {
    pub fingerprint: String,
    pub ts: i64,
    pub admit: Option<String>,
}

/// Parse and verify the `Authorization` header a handle sends on every route
/// after `/push`.
///
/// Expected format: `Ed25519 fingerprint=<fp> ts=<ts> sig=<sig> [admit=<tag>]`
///
/// Returns the verified handle on success. The tag is not checked here — whether
/// it is needed is the rule's question (`Admission::admit`).
pub fn verify_lookup_auth(header: &str) -> Result<Handle, AuthError> {
    // Strip "Ed25519 " prefix
    let rest = header
        .strip_prefix("Ed25519 ")
        .ok_or(AuthError::MalformedAuth)?;

    // Parse key=value pairs separated by spaces
    let mut fp: Option<&str> = None;
    let mut ts: Option<i64> = None;
    let mut sig: Option<&str> = None;
    let mut admit: Option<&str> = None;

    for part in rest.split_whitespace() {
        if let Some(v) = part.strip_prefix("fingerprint=") {
            fp = Some(v);
        } else if let Some(v) = part.strip_prefix("ts=") {
            ts = v.parse().ok();
        } else if let Some(v) = part.strip_prefix("sig=") {
            sig = Some(v);
        } else if let Some(v) = part.strip_prefix("admit=") {
            admit = Some(v);
        }
    }

    let fp = fp.ok_or(AuthError::MalformedAuth)?.to_owned();
    let ts = ts.ok_or(AuthError::MalformedAuth)?;
    let sig = sig.ok_or(AuthError::MalformedAuth)?;

    // Verify timestamp
    verify_timestamp(ts)?;

    // Verify signature over "{fingerprint}\n{ts}"
    let verifying_key = ed25519_key_from_did(&fp)?;
    let message = format!("{}\n{}", fp, ts);
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(sig)
        .map_err(|e| AuthError::SigDecode(e.to_string()))?;
    let sig_arr: [u8; 64] = sig_bytes
        .as_slice()
        .try_into()
        .map_err(|_| AuthError::SigDecode(format!("expected 64 bytes, got {}", sig_bytes.len())))?;
    let signature = Signature::from_bytes(&sig_arr);
    use ed25519_dalek::Verifier as _;
    verifying_key
        .verify(message.as_bytes(), &signature)
        .map_err(|_| AuthError::BadSignature)?;

    Ok(Handle {
        fingerprint: fp,
        ts,
        admit: admit.map(str::to_owned),
    })
}

/// Parse and verify an operator's `Authorization` header over `body`.
///
/// Expected format: `KottonOperator key=<64 hex> ts=<ts> sig=<base64url>`, the
/// signature over [`kotton_wire::rendezvous::operator_signing_input`]. A scheme of
/// its own, so a handle's header is never read as an operator's or the reverse.
///
/// Returns the key (hex) and the timestamp. Whether the key *is* an operator is
/// the caller's next question.
pub fn verify_operator_auth(header: &str, body: &[u8]) -> Result<(String, i64), AuthError> {
    let rest = header
        .strip_prefix("KottonOperator ")
        .ok_or(AuthError::MalformedAuth)?;
    let (mut key, mut ts, mut sig) = (None, None, None);
    for part in rest.split_whitespace() {
        if let Some(v) = part.strip_prefix("key=") {
            key = Some(v);
        } else if let Some(v) = part.strip_prefix("ts=") {
            ts = v.parse::<i64>().ok();
        } else if let Some(v) = part.strip_prefix("sig=") {
            sig = Some(v);
        }
    }
    let key = key.ok_or(AuthError::MalformedAuth)?;
    let ts = ts.ok_or(AuthError::MalformedAuth)?;
    let sig = sig.ok_or(AuthError::MalformedAuth)?;
    verify_timestamp(ts)?;

    let raw = hex_32(key).ok_or(AuthError::WrongKeyLength(key.len() / 2))?;
    let verifying_key =
        VerifyingKey::from_bytes(&raw).map_err(|e| AuthError::InvalidKey(e.to_string()))?;
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(sig)
        .map_err(|e| AuthError::SigDecode(e.to_string()))?;
    let sig_arr: [u8; 64] = sig_bytes
        .as_slice()
        .try_into()
        .map_err(|_| AuthError::SigDecode(format!("expected 64 bytes, got {}", sig_bytes.len())))?;
    use ed25519_dalek::Verifier as _;
    verifying_key
        .verify(
            &kotton_wire::rendezvous::operator_signing_input(key, ts, body),
            &Signature::from_bytes(&sig_arr),
        )
        .map_err(|_| AuthError::BadSignature)?;
    Ok((key.to_owned(), ts))
}

fn hex_32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 || !s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        out[i] = u8::from_str_radix(std::str::from_utf8(chunk).ok()?, 16).ok()?;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    fn make_key() -> (SigningKey, String) {
        let sk = SigningKey::generate(&mut OsRng);
        let vk = sk.verifying_key();
        // Build did:key fingerprint manually
        let mut prefixed = vec![0xed_u8, 0x01];
        prefixed.extend_from_slice(vk.as_bytes());
        let b58 = bs58::encode(&prefixed).into_string();
        let did = format!("did:key:z{}", b58);
        (sk, did)
    }

    #[test]
    fn round_trip_did_key_extraction() {
        let (sk, did) = make_key();
        let extracted = ed25519_key_from_did(&did).unwrap();
        assert_eq!(extracted, sk.verifying_key());
    }

    #[test]
    fn push_sig_verify_ok() {
        use ed25519_dalek::Signer;
        let (sk, did) = make_key();
        let addr = "203.0.113.45:4444";
        let ts: i64 = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let msg = format!("{}\n{}\n{}\n\n{}", did, addr, ts, true);
        let sig_bytes = sk.sign(msg.as_bytes()).to_bytes();
        let sig_b64 = URL_SAFE_NO_PAD.encode(sig_bytes);

        let vk = ed25519_key_from_did(&did).unwrap();
        verify_push_sig(&vk, &did, addr, ts, None, true, &sig_b64).unwrap();
    }

    #[test]
    fn push_sig_verify_fails_on_tampered_addr() {
        use ed25519_dalek::Signer;
        let (sk, did) = make_key();
        let ts: i64 = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let msg = format!("{}\n{}\n{}\n\n{}", did, "203.0.113.45:4444", ts, true);
        let sig_bytes = sk.sign(msg.as_bytes()).to_bytes();
        let sig_b64 = URL_SAFE_NO_PAD.encode(sig_bytes);

        let vk = ed25519_key_from_did(&did).unwrap();
        // Use a different addr — signature should fail
        let result = verify_push_sig(&vk, &did, "10.0.0.1:9999", ts, None, true, &sig_b64);
        assert!(matches!(result, Err(AuthError::BadSignature)));
    }
}
