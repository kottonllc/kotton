// SPDX-License-Identifier: AGPL-3.0-or-later
//! What makes a relay *this relay*: the key it proves, not the spelling of its
//! address.
//!
//! [`prove_relay`] is the one place a device asks a relay who it is. It dials the
//! URL — where the key was last found, a hint — asks the relay to sign a nonce
//! this device chose, and believes the key only if the signature holds. A caller
//! that expects a key refuses any other, so a stranger answering at the same
//! address is refused by anyone who has seen the relay before. A caller that
//! expects none records what it was shown, and from then on expects it.
//!
//! **Nothing here compares URLs**, and nothing may: two spellings of one address
//! are one relay, one relay at a new address is the same relay, and a different
//! key at the old address is a stranger. The address the relay announces comes
//! back inside the signature and is not checked against how it was dialled —
//! it is the relay's word about itself, and the key is what is believed.
//!
//! The transport is untouched: plain HTTP stays plain. What an observer on the
//! path could do before, it can still do; what changes is that a stand-in at the
//! address cannot answer with the relay's key.

use std::time::Duration;

use ed25519_dalek::{Signature, VerifyingKey};
use kotton_wire::rendezvous::identity_signing_input;
use rand::RngCore as _;

/// How long a relay has to answer who it is. Short: a person naming a relay is
/// waiting on it, and a relay that cannot answer in this long is not shown.
pub const PROVE_TIMEOUT: Duration = Duration::from_secs(5);

/// Why a relay's key was not believed.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RelayKeyError {
    /// The relay answered with a key and could not prove it: a key or signature
    /// that does not decode, or a signature that does not verify over this
    /// device's nonce. Refused whether or not a key was expected — a relay that
    /// claims a key and cannot sign for it is not shown one. A body that is not
    /// an identity at all is read as nothing shown, as no answer is: `Ok(None)`
    /// at first sight, [`RelayKeyError::Stranger`] where a key was expected.
    #[error("the relay at {url} answered with a key it could not prove ({why})")]
    NotProven { url: String, why: String },
    /// A key was expected and the relay at the address proved another, or none.
    #[error(
        "the relay at {url} is not the relay this device knows: it expected key {expected} and \
         was shown {}", shown.as_deref().unwrap_or("none")
    )]
    Stranger { url: String, expected: String, shown: Option<String> },
}

/// Dial the relay at `url`, and return the key it proves.
///
/// - **`expected` is `Some`**: the relay must prove exactly that key. Another
///   key, no key, or no answer is refused as [`RelayKeyError::Stranger`] — a
///   device that knows its relay does not take the word of whatever answers at
///   the address.
/// - **`expected` is `None`**: this is first sight. A proven key is returned for
///   the caller to record beside the URL; a relay that keeps no key, or does not
///   answer, returns `Ok(None)` — nothing was shown, so nothing is recorded, and
///   the device trusts the URL exactly as it did before relays had keys.
///
/// A relay that answers with a key it cannot prove is refused in both cases
/// ([`RelayKeyError::NotProven`]).
pub async fn prove_relay(url: &str, expected: Option<&[u8; 32]>) -> Result<Option<[u8; 32]>, RelayKeyError> {
    let mut nonce = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let shown = match kotton_net::rendezvous::fetch_relay_identity(url, &nonce, PROVE_TIMEOUT).await {
        Ok(Some(id)) => Some(verify(url, &nonce, &id)?),
        // No key kept, or no answer: nothing was shown.
        Ok(None) => None,
        Err(e) => {
            tracing::debug!(url, error = %e, "the relay did not answer who it is");
            None
        }
    };
    match (expected, shown) {
        (Some(want), Some(got)) if *want == got => Ok(Some(got)),
        (Some(want), shown) => Err(RelayKeyError::Stranger {
            url: url.to_owned(),
            expected: hex::encode(want),
            shown: shown.map(hex::encode),
        }),
        (None, shown) => Ok(shown),
    }
}

/// The relay key to keep beside a relay's URL, from the key already `named` for
/// it — recorded on the device, or written in an operator credential — and what
/// the relay at the address `proved` when asked with that key expected. One
/// policy for every verb that names a relay: a key proved is kept;
/// a named key the relay did not show, with no other shown, stays as named (the
/// relay may be down); another key shown where one was named, or a key the
/// relay could not prove, refuses the verb.
pub fn key_to_keep(
    named: Option<[u8; 32]>,
    proved: Result<Option<[u8; 32]>, RelayKeyError>,
) -> Result<Option<[u8; 32]>, RelayKeyError> {
    match proved {
        Ok(shown) => Ok(shown.or(named)),
        Err(RelayKeyError::Stranger { shown: None, .. }) => Ok(named),
        Err(e) => Err(e),
    }
}

/// The key in `id`, if its signature over `nonce` and the address it announces
/// verifies under it.
fn verify(
    url: &str,
    nonce: &[u8],
    id: &kotton_wire::rendezvous::RelayIdentity,
) -> Result<[u8; 32], RelayKeyError> {
    let not_proven = |why: &str| RelayKeyError::NotProven { url: url.to_owned(), why: why.to_owned() };
    let key: [u8; 32] = hex::decode(&id.key)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| not_proven("its key is not 32 bytes of hex"))?;
    let sig: [u8; 64] = hex::decode(&id.sig)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| not_proven("its signature is not 64 bytes of hex"))?;
    let vk = VerifyingKey::from_bytes(&key).map_err(|_| not_proven("its key is not a point"))?;
    vk.verify_strict(&identity_signing_input(nonce, &id.addr), &Signature::from_bytes(&sig))
        .map_err(|_| not_proven("the signature does not verify over this device's nonce"))?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer as _, SigningKey};
    use kotton_wire::rendezvous::RelayIdentity;
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    /// What the stand-in answers at `/identity`.
    #[derive(Clone)]
    enum Answer {
        /// A proof under this key, over the nonce asked and this address.
        Prove(SigningKey, &'static str),
        /// A proof under this key over a nonce nobody asked for — a replay.
        Replay(SigningKey),
        /// `404`, as a relay with no key answers.
        NoKey,
    }

    /// A relay at one address whose answer the test changes underneath it: the
    /// same URL, first the relay, then a stand-in.
    async fn relay_at() -> (String, Arc<Mutex<Answer>>) {
        let answer = Arc::new(Mutex::new(Answer::NoKey));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let held = answer.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut s, _)) = listener.accept().await else { return };
                let answer = held.lock().unwrap().clone();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096];
                    let n = s.read(&mut buf).await.unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]).to_string();
                    let nonce_hex = req
                        .split_once("nonce=")
                        .and_then(|(_, r)| r.split([' ', '&']).next())
                        .unwrap_or("")
                        .to_owned();
                    let nonce = hex::decode(nonce_hex).unwrap_or_default();
                    let (status, body) = match answer {
                        Answer::Prove(sk, addr) => (200, proof(&sk, &nonce, addr)),
                        Answer::Replay(sk) => (200, proof(&sk, &[0u8; 32], "")),
                        Answer::NoKey => (404, r#"{"error":"this relay keeps no key"}"#.to_owned()),
                    };
                    let resp = format!(
                        "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = s.write_all(resp.as_bytes()).await;
                });
            }
        });
        (url, answer)
    }

    fn proof(sk: &SigningKey, nonce: &[u8], addr: &str) -> String {
        serde_json::to_string(&RelayIdentity {
            key: hex::encode(sk.verifying_key().as_bytes()),
            addr: addr.to_owned(),
            sig: hex::encode(sk.sign(&identity_signing_input(nonce, addr)).to_bytes()),
        })
        .unwrap()
    }

    fn key(b: u8) -> SigningKey {
        SigningKey::from_bytes(&[b; 32])
    }

    /// Clause 5's heart: a stand-in answering at the relay's own address, with
    /// the relay's own URL spelled the same way, is refused by a device that
    /// expects the relay's key — and taken by one that has never seen a key,
    /// which is what first sight is.
    #[tokio::test]
    async fn a_stand_in_at_the_same_address_is_refused_when_a_key_is_expected_and_taken_when_none_is() {
        let (url, answer) = relay_at().await;
        let relay = key(1);
        *answer.lock().unwrap() = Answer::Prove(relay.clone(), "relay.example:7700");

        // First sight: the relay's key, proven, for the caller to record.
        let recorded = prove_relay(&url, None).await.unwrap().expect("the relay proves a key");
        assert_eq!(recorded, relay.verifying_key().to_bytes());
        // From then on it is expected, and the relay proves it again.
        assert_eq!(prove_relay(&url, Some(&recorded)).await, Ok(Some(recorded)));

        // A stand-in takes the address. It holds a key of its own and signs
        // honestly under it — and it is not the relay.
        let stand_in = key(2);
        *answer.lock().unwrap() = Answer::Prove(stand_in.clone(), "relay.example:7700");
        let refused = prove_relay(&url, Some(&recorded)).await;
        assert_eq!(
            refused,
            Err(RelayKeyError::Stranger {
                url: url.clone(),
                expected: hex::encode(recorded),
                shown: Some(hex::encode(stand_in.verifying_key().as_bytes())),
            }),
            "a device that knows its relay refuses a stranger at its address"
        );
        // A device that has never seen a key takes what it is shown.
        assert_eq!(
            prove_relay(&url, None).await,
            Ok(Some(stand_in.verifying_key().to_bytes())),
            "first sight takes the key shown"
        );
    }

    /// A stand-in cannot pass by showing no key: when one is expected, a relay
    /// that keeps none, or nothing answering at all, is refused the same way.
    #[tokio::test]
    async fn an_expected_key_is_not_answered_by_no_key_or_by_silence() {
        let (url, answer) = relay_at().await;
        let known = key(1).verifying_key().to_bytes();
        *answer.lock().unwrap() = Answer::NoKey;
        assert!(matches!(
            prove_relay(&url, Some(&known)).await,
            Err(RelayKeyError::Stranger { shown: None, .. })
        ));
        // Nothing expected, nothing shown: nothing to record.
        assert_eq!(prove_relay(&url, None).await, Ok(None));

        // Nothing listening at all.
        let silent = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            format!("http://{}", l.local_addr().unwrap())
        };
        assert!(matches!(
            prove_relay(&silent, Some(&known)).await,
            Err(RelayKeyError::Stranger { shown: None, .. })
        ));
        assert_eq!(prove_relay(&silent, None).await, Ok(None), "an unreachable relay shows nothing");
    }

    /// A relay that presents a key and cannot sign this device's nonce with it —
    /// a proof captured from someone else's dial and replayed — is refused, with
    /// or without an expected key.
    #[tokio::test]
    async fn a_replayed_proof_is_refused_even_at_first_sight() {
        let (url, answer) = relay_at().await;
        let relay = key(1);
        *answer.lock().unwrap() = Answer::Replay(relay.clone());
        assert!(matches!(prove_relay(&url, None).await, Err(RelayKeyError::NotProven { .. })));
        assert!(matches!(
            prove_relay(&url, Some(&relay.verifying_key().to_bytes())).await,
            Err(RelayKeyError::NotProven { .. })
        ));
    }

    /// Two spellings of one address are one relay: the key decides, and no
    /// spelling of the URL is compared.
    #[tokio::test]
    async fn two_spellings_of_one_address_are_one_relay() {
        let (url, answer) = relay_at().await;
        let relay = key(3);
        *answer.lock().unwrap() = Answer::Prove(relay.clone(), "");
        let known = relay.verifying_key().to_bytes();
        let respelled = format!("{}/", url.replace("http://", "HTTP://"));
        assert_eq!(prove_relay(&respelled, Some(&known)).await, Ok(Some(known)));
    }
}
