// SPDX-License-Identifier: AGPL-3.0-or-later
//! Servicing a confined extension's host calls (RFC-0049; Sprint 03 Phase 3c).
//!
//! This is the daemon side of the boundary [`kotton_outbound::policy`] and
//! [`crate::quarantine`] each guard half of. A fetcher runs in the
//! `kotton-runner` process and asks for capabilities that process deliberately
//! does not hold; every such ask arrives here as a [`RunnerHostCall`] and
//! leaves as a [`RunnerHostReply`].
//!
//! It is the first place the two halves of the fetcher's confinement compose:
//!
//! - [`ExtensionNetPolicy`] decides whether a destination is permitted **before
//!   resolving any credential**, then injects host-held material only toward
//!   destinations the author declared and the user consented to.
//! - [`Quarantine`] accepts writes into this extension's own namespace and
//!   reads back only what it wrote — and offers no verb that could reach the
//!   user's store.
//!
//! Nothing here re-derives those rules; it routes to them. That is deliberate:
//! one enforcement point per rule, so there is no second copy to drift.
//!
//! ## Errors are the guest's to see, not the host's to hide
//!
//! A refusal is returned to the extension as a typed error it can handle —
//! retry a different endpoint, report to the user, give up. It is *not* a trap
//! and not a silent empty result. A fetcher that asks for something it may not
//! have should learn that it may not have it; hiding the refusal would only
//! make extensions harder to debug without making them any less confined.

use std::sync::Mutex;

use kotton_sys::outbound::{
    CredentialRef, HeaderText, HeaderValue, OutboundRequest, OutboundResponse,
};
use kotton_wire::runner::{
    HostHeaderValue, HostRequest, HostResponse, RunnerHostCall, RunnerHostReply,
};

use crate::quarantine::Quarantine;
use kotton_outbound::ExtensionNetPolicy;

/// Services host calls for one running extension.
pub struct ExtensionHost {
    net: ExtensionNetPolicy,
    quarantine: Quarantine,
    /// Quarantine keys written during the current cycle, in write order.
    ///
    /// Reported back in `RunnerOutput::Fetched { wrote }` so the daemon can
    /// surface what arrived for promotion **without reading quarantine content
    /// itself** — the host stays out of the ingress data path.
    wrote: Mutex<Vec<String>>,
}

impl ExtensionHost {
    pub fn new(net: ExtensionNetPolicy, quarantine: Quarantine) -> Self {
        Self {
            net,
            quarantine,
            wrote: Mutex::new(Vec::new()),
        }
    }

    /// Keys written this cycle, in order, without duplicates.
    pub fn keys_written(&self) -> Vec<String> {
        let wrote = self.wrote.lock().expect("wrote lock");
        let mut seen = std::collections::HashSet::new();
        wrote
            .iter()
            .filter(|k| seen.insert((*k).clone()))
            .cloned()
            .collect()
    }

    /// Handle one host call. Never panics and never returns `Err`: a failure is
    /// data the extension receives, not a fault the daemon propagates.
    pub async fn service(&self, call: RunnerHostCall) -> RunnerHostReply {
        match call {
            RunnerHostCall::NetRequest { request } => self.net_request(request).await,
            RunnerHostCall::QuarantineWrite { key, content } => {
                match self.quarantine.write(&key, &content).await {
                    Ok(()) => {
                        self.wrote.lock().expect("wrote lock").push(key);
                        RunnerHostReply::QuarantineWritten
                    }
                    Err(e) => RunnerHostReply::QuarantineError {
                        message: e.to_string(),
                    },
                }
            }
            RunnerHostCall::QuarantineReadOwn { key } => {
                match self.quarantine.read_own(&key).await {
                    Ok(content) => RunnerHostReply::QuarantineContent { content },
                    Err(e) => RunnerHostReply::QuarantineError {
                        message: e.to_string(),
                    },
                }
            }
            // A fetcher's world imports `external-net`, `quarantine` and
            // `fetch-env` — nothing else exists in it, so there is no path by
            // which its guest could call auth. A frame that arrives here
            // anyway did not come from the guest; it came from a runner that
            // is not doing what a runner does. Refusing it is the point: this
            // is the one place the two host-call families meet, and they must
            // not be serviceable from the same seat (DEC-0045).
            RunnerHostCall::Auth { .. } => RunnerHostReply::QuarantineError {
                message: "a fetcher cannot make an auth call; its world has no such import"
                    .to_string(),
            },
            // Refused for the same reason and written out separately rather than
            // folded into a catch-all: this match is where the two host-call
            // families meet, and a reader should be able to see that *every*
            // occupant verb is refused here, not infer it from a wildcard that
            // would also silently swallow a family added later.
            RunnerHostCall::Messages { .. }
            | RunnerHostCall::Contacts { .. }
            | RunnerHostCall::Network { .. }
            | RunnerHostCall::Joining { .. }
            | RunnerHostCall::Records { .. }
            | RunnerHostCall::Landlord { .. }
            | RunnerHostCall::Operators { .. }
            | RunnerHostCall::Grants { .. }
            | RunnerHostCall::Devices { .. } => RunnerHostReply::QuarantineError {
                message: "a fetcher cannot make a messages, contacts, network, joining, records, landlord, operators, grants or devices call; its world has no such import"
                    .to_string(),
            },
            // `infer` lives in `world app`, and a fetcher holds `world fetcher`.
            // Its own arm rather than joining the three above, because those
            // three answer with one message naming only `devices` — a `messages`
            // frame is refused here and told it was a devices call, which is a
            // diagnostic that sends a reader to the wrong import. Adding a
            // fourth family to that group would widen a defect instead of
            // leaving it where it can be seen.
            RunnerHostCall::Infer { .. } => RunnerHostReply::QuarantineError {
                message: "a fetcher cannot make an infer call; its world has no such import"
                    .to_string(),
            },
            // A fetcher draws nothing. `world fetcher` imports neither `surface`
            // nor `layer-surface` — an extension has no window, which is most of
            // what makes it an extension — so a surface frame from one is a
            // runner emitting a call it could not have been asked for. Its own
            // arm, for the reason `infer` has one: the message should name the
            // import the caller does not have.
            RunnerHostCall::Surface { .. } => RunnerHostReply::QuarantineError {
                message: "a fetcher cannot ask for a surface; its world has no such import"
                    .to_string(),
            },
            // `schema` lives in `world app`, and a fetcher holds `world fetcher`,
            // which reads nothing of the person's (RFC-0049): a kept-records
            // frame from one is a runner emitting a call its world cannot make.
            // Its own arm, for the reason `infer` has one.
            RunnerHostCall::Kept { .. } => RunnerHostReply::QuarantineError {
                message: "a fetcher cannot read a person's records; its world has no such import"
                    .to_string(),
            },
            // `world fetcher` imports no `files`: an extension writes what it
            // fetched into its quarantine namespace and nowhere in the person's
            // tree. Its own arm, for the reason `surface` has one.
            RunnerHostCall::Files { .. } => RunnerHostReply::QuarantineError {
                message: "a fetcher cannot make a files call; its world has no such import"
                    .to_string(),
            },
            RunnerHostCall::QuarantineListOwn { prefix } => {
                match self.quarantine.list_own(&prefix).await {
                    Ok(keys) => RunnerHostReply::QuarantineKeys { keys },
                    Err(e) => RunnerHostReply::QuarantineError {
                        message: e.to_string(),
                    },
                }
            }
        }
    }

    async fn net_request(&self, request: HostRequest) -> RunnerHostReply {
        let outbound = OutboundRequest {
            method: request.method,
            url: request.url,
            headers: request
                .headers
                .into_iter()
                .map(|(name, value)| {
                    let value = match value {
                        // From the wire's redacting type straight into the
                        // mediator's: the literal is never held as plain text.
                        HostHeaderValue::Literal { value } => {
                            HeaderValue::Literal(HeaderText::new(value.expose()))
                        }
                        HostHeaderValue::Credential { credential } => HeaderValue::Credential(
                            CredentialRef::new(credential.slot, credential.template),
                        ),
                    };
                    (name, value)
                })
                .collect(),
            body: request.body,
        };

        match self.net.request(outbound).await {
            Ok(OutboundResponse {
                status,
                headers,
                body,
            }) => RunnerHostReply::NetResponse {
                response: HostResponse {
                    status,
                    headers,
                    body,
                },
            },
            Err(e) => RunnerHostReply::NetError {
                message: e.to_string(),
            },
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::quarantine::Quarantine;
    use async_trait::async_trait;
    use kotton_schemas::{CapabilityGrant, CapabilityKind, CapabilitySet, CapabilityTarget};
    use kotton_store::MemoryObjectStorage;
    use kotton_sys::outbound::{DestinationPolicy, EndpointPattern, NetMediator, NetResult};
    use kotton_sys::secret::{SecretsResult, SecretsStore};
    use kotton_sys::store::ObjectStorage;
    use std::sync::Arc;

    const EXT: &str = "sh.kotton.feed-reader";

    /// Records what reached the transport — the only place credential
    /// substitution is observable.
    #[derive(Default)]
    struct RecordingMediator {
        seen: Mutex<Vec<OutboundRequest>>,
    }

    #[async_trait]
    impl NetMediator for RecordingMediator {
        async fn perform(&self, request: OutboundRequest) -> NetResult<OutboundResponse> {
            self.seen.lock().unwrap().push(request);
            Ok(OutboundResponse {
                status: 200,
                headers: vec![("content-type".into(), "application/xml".into())],
                body: b"<rss><item>hello</item></rss>".to_vec(),
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
        fn set_secret(&self, _k: &str, _v: &str) -> SecretsResult<()> {
            Ok(())
        }
        fn delete_secret(&self, _k: &str) -> SecretsResult<()> {
            Ok(())
        }
    }

    fn grants() -> CapabilitySet {
        let target = CapabilityTarget::Quarantine {
            extension_id: EXT.to_string(),
        };
        CapabilitySet::new(vec![
            CapabilityGrant {
                kind: CapabilityKind::Write,
                target: target.clone(),
            },
            CapabilityGrant {
                kind: CapabilityKind::Read,
                target,
            },
        ])
    }

    fn host_with(
        patterns: &[&str],
        secrets: Vec<(String, String)>,
    ) -> (
        ExtensionHost,
        Arc<RecordingMediator>,
        Arc<dyn ObjectStorage>,
    ) {
        let mediator = Arc::new(RecordingMediator::default());
        let store: Arc<dyn ObjectStorage> = Arc::new(MemoryObjectStorage::new());
        let net = ExtensionNetPolicy::new(
            EXT,
            DestinationPolicy::declared(
                patterns
                    .iter()
                    .map(|p| EndpointPattern::parse(p).unwrap())
                    .collect(),
            ),
            mediator.clone(),
            Arc::new(FakeSecrets(secrets)),
        );
        let quarantine = Quarantine::new(EXT, grants(), store.clone());
        (ExtensionHost::new(net, quarantine), mediator, store)
    }

    fn get(url: &str) -> RunnerHostCall {
        RunnerHostCall::NetRequest {
            request: HostRequest {
                method: "GET".into(),
                url: url.into(),
                headers: vec![],
                body: vec![],
            },
        }
    }

    /// The shape of a real fetch cycle, end to end at the daemon boundary:
    /// reach a declared endpoint, land the bytes in quarantine, report what
    /// arrived.
    #[tokio::test]
    async fn a_fetch_cycle_reaches_the_net_and_lands_in_quarantine() {
        let (host, mediator, _store) = host_with(&["example.com"], vec![]);

        let RunnerHostReply::NetResponse { response } =
            host.service(get("https://example.com/feed.xml")).await
        else {
            panic!("declared endpoint must be permitted");
        };
        assert_eq!(response.status, 200);

        let reply = host
            .service(RunnerHostCall::QuarantineWrite {
                key: "feed.xml".into(),
                content: response.body.clone(),
            })
            .await;
        assert!(matches!(reply, RunnerHostReply::QuarantineWritten));

        // Read-own works, so incremental fetch has somewhere to keep state.
        let reply = host
            .service(RunnerHostCall::QuarantineReadOwn {
                key: "feed.xml".into(),
            })
            .await;
        let RunnerHostReply::QuarantineContent { content } = reply else {
            panic!("read-own must return what was written");
        };
        assert_eq!(content, b"<rss><item>hello</item></rss>");

        assert_eq!(host.keys_written(), vec!["feed.xml".to_string()]);
        assert_eq!(mediator.seen.lock().unwrap().len(), 1);
    }

    /// The confinement, at the only layer that can enforce it: an undeclared
    /// destination is refused and never reaches the transport.
    #[tokio::test]
    async fn an_undeclared_destination_is_refused_and_never_dialed() {
        let (host, mediator, _store) = host_with(&["example.com"], vec![]);

        let reply = host.service(get("https://evil.test/collect")).await;
        let RunnerHostReply::NetError { message } = reply else {
            panic!("an undeclared destination must be refused");
        };
        assert!(message.contains("evil.test"), "got: {message}");
        assert!(
            mediator.seen.lock().unwrap().is_empty(),
            "a refused request must not reach the transport at all"
        );
    }

    /// Credentials are resolved host-side, only for permitted destinations, and
    /// the resolved material exists nowhere the extension could observe it.
    #[tokio::test]
    async fn a_credential_is_injected_only_toward_a_declared_destination() {
        let key = kotton_sys::secret::prefix_key(&format!("extension/{EXT}/credential/api-token"));
        let (host, mediator, _store) =
            host_with(&["api.example.com"], vec![(key, "SUPER-SECRET".into())]);

        let call = RunnerHostCall::NetRequest {
            request: HostRequest {
                method: "GET".into(),
                url: "https://api.example.com/v1/events".into(),
                headers: vec![(
                    "authorization".into(),
                    HostHeaderValue::Credential {
                        credential: kotton_wire::runner::HostCredentialRef {
                            slot: "api-token".into(),
                            template: "Bearer {}".into(),
                        },
                    },
                )],
                body: vec![],
            },
        };
        let reply = host.service(call).await;
        assert!(matches!(reply, RunnerHostReply::NetResponse { .. }));

        // Resolved on the wire...
        let seen = mediator.seen.lock().unwrap();
        let (_, value) = seen[0]
            .headers
            .iter()
            .find(|(n, _)| n == "authorization")
            .expect("authorization header");
        assert_eq!(value, &HeaderValue::Literal(HeaderText::new("Bearer SUPER-SECRET")));

        // ...and nowhere in what would travel back to the runner.
        let serialized = serde_json::to_string(&reply).unwrap();
        assert!(
            !serialized.contains("SUPER-SECRET"),
            "resolved material must never travel back toward the guest: {serialized}"
        );
    }

    /// A quarantine escape attempt is refused as data the guest can see, and
    /// nothing lands outside the namespace.
    #[tokio::test]
    async fn a_quarantine_escape_is_refused_without_writing_anything() {
        let (host, _mediator, store) = host_with(&["example.com"], vec![]);

        let reply = host
            .service(RunnerHostCall::QuarantineWrite {
                key: "../../../home/notes/todo.md".into(),
                content: b"evil".to_vec(),
            })
            .await;
        let RunnerHostReply::QuarantineError { message } = reply else {
            panic!("an escaping key must be refused");
        };
        assert!(message.contains("may not contain"), "got: {message}");

        assert!(
            host.keys_written().is_empty(),
            "a refused write is not a write"
        );
        let listed = store.list(std::path::Path::new("")).await.unwrap();
        assert!(
            listed.iter().filter(|e| !e.is_dir).count() == 0,
            "nothing may land outside the namespace"
        );
    }

    /// A missing credential is a clean, guest-visible error rather than a
    /// request that silently goes out unauthenticated.
    #[tokio::test]
    async fn a_missing_credential_slot_fails_the_request() {
        let (host, mediator, _store) = host_with(&["api.example.com"], vec![]);

        let call = RunnerHostCall::NetRequest {
            request: HostRequest {
                method: "GET".into(),
                url: "https://api.example.com/v1/events".into(),
                headers: vec![(
                    "authorization".into(),
                    HostHeaderValue::Credential {
                        credential: kotton_wire::runner::HostCredentialRef {
                            slot: "absent".into(),
                            template: "Bearer {}".into(),
                        },
                    },
                )],
                body: vec![],
            },
        };
        let RunnerHostReply::NetError { message } = host.service(call).await else {
            panic!("a missing slot must fail the request");
        };
        assert!(message.contains("absent"), "got: {message}");
        assert!(
            mediator.seen.lock().unwrap().is_empty(),
            "an unauthenticated request must not go out in place of an authenticated one"
        );
    }

    #[tokio::test]
    async fn written_keys_are_reported_once_each_in_order() {
        let (host, _m, _s) = host_with(&["example.com"], vec![]);
        for key in ["a.xml", "b.xml", "a.xml"] {
            host.service(RunnerHostCall::QuarantineWrite {
                key: key.into(),
                content: b"x".to_vec(),
            })
            .await;
        }
        assert_eq!(
            host.keys_written(),
            vec!["a.xml".to_string(), "b.xml".to_string()]
        );
    }
}
