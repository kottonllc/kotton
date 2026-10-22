// SPDX-License-Identifier: AGPL-3.0-or-later
//! `kotton-providers-net-mediator` — the HTTP implementation of the outbound
//! mediator contract (RFC-0049; Sprint 03 Phase 1).
//!
//! This crate performs requests that policy has already authorized. It owns
//! exactly three jobs, in order:
//!
//! 1. **Resolve and vet.** The destination host is resolved first, and *every*
//!    resolved address is checked against
//!    [`kotton_sys::outbound::is_forbidden_destination`]. One
//!    forbidden address refuses the whole request — a name that resolves to
//!    both a public and a private address is a rebinding attempt, not a
//!    fallback. The vetted addresses are then **pinned** for the connection,
//!    so the request can only reach what was checked (TLS still verifies
//!    against the hostname).
//! 2. **Perform, without following redirects.** A redirect is a new
//!    destination, and destinations are policy decisions made *above* this
//!    crate — so a 3xx is returned to the caller, never chased.
//! 3. **Bound the response.** Bodies are read in chunks and refused past
//!    [`MAX_RESPONSE_BYTES`] — the mediator is not a buffer for whatever a
//!    server decides to send.
//!
//! What this crate deliberately does **not** know about: extensions,
//! manifests, endpoint patterns, or credentials. The runtime (tier 05)
//! resolves policy and credentials first; if a request still carrying an
//! unresolved [`HeaderValue::Credential`] reaches this crate, that is a bug
//! upstream and the request is refused.

use std::net::SocketAddr;
use std::time::Duration;

use async_trait::async_trait;
use kotton_sys::outbound::{
    is_forbidden_destination, HeaderValue, NetError, NetMediator, NetResult, OutboundRequest,
    OutboundResponse, MAX_RESPONSE_BYTES,
};
use url::{Host, Url};

/// Wall-clock ceiling for a single mediated request.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

/// The reqwest-backed [`NetMediator`].
pub struct HttpNetMediator {
    /// Test-only escape hatch: permit loopback/private destinations so tests
    /// can run against a local listener. Production construction ([`new`])
    /// never sets this; the field cannot be reached from outside the crate's
    /// constructors.
    ///
    /// [`new`]: HttpNetMediator::new
    allow_forbidden: bool,
}

impl HttpNetMediator {
    /// A production mediator: local/private destinations are always refused.
    pub fn new() -> Self {
        Self {
            allow_forbidden: false,
        }
    }

    /// A mediator that may reach loopback — for tests that stand up a local
    /// server. Never construct this on a production path: it removes the LAN
    /// guard, which is the one *forced* network restriction in RFC-0049.
    pub fn dangerously_allow_local_for_tests() -> Self {
        Self {
            allow_forbidden: true,
        }
    }

    /// Resolve the URL's host and return the vetted socket addresses to pin.
    ///
    /// Errors with [`NetError::DestinationRefused`] if any resolved address is
    /// forbidden (unless the test escape hatch is set).
    async fn resolve_and_vet(&self, url: &Url) -> NetResult<Vec<SocketAddr>> {
        let port = url
            .port_or_known_default()
            .ok_or_else(|| NetError::Malformed("URL has no usable port".into()))?;
        let addrs: Vec<SocketAddr> = match url
            .host()
            .ok_or_else(|| NetError::Malformed("URL has no host".into()))?
        {
            Host::Ipv4(ip) => vec![SocketAddr::new(ip.into(), port)],
            Host::Ipv6(ip) => vec![SocketAddr::new(ip.into(), port)],
            Host::Domain(domain) => tokio::net::lookup_host((domain, port))
                .await
                .map_err(|e| NetError::Transport(format!("resolve {domain}: {e}")))?
                .collect(),
        };
        if addrs.is_empty() {
            return Err(NetError::Transport("destination resolved to nothing".into()));
        }
        if !self.allow_forbidden {
            if let Some(bad) = addrs.iter().find(|a| is_forbidden_destination(a.ip())) {
                return Err(NetError::DestinationRefused(format!(
                    "{} resolves to {}, a local or non-routable address",
                    url.host_str().unwrap_or("<none>"),
                    bad.ip()
                )));
            }
        }
        Ok(addrs)
    }
}

impl Default for HttpNetMediator {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl NetMediator for HttpNetMediator {
    async fn perform(&self, request: OutboundRequest) -> NetResult<OutboundResponse> {
        let url = Url::parse(&request.url)
            .map_err(|e| NetError::Malformed(format!("bad URL: {e}")))?;
        if url.scheme() != "https" && url.scheme() != "http" {
            return Err(NetError::Malformed(format!(
                "scheme `{}` is not mediated",
                url.scheme()
            )));
        }

        let addrs = self.resolve_and_vet(&url).await?;

        let mut builder = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(REQUEST_TIMEOUT)
            .use_rustls_tls();
        // Pin the connection to the addresses that were just vetted; a second
        // resolution (rebinding) can no longer change where this connects.
        if let Some(Host::Domain(domain)) = url.host() {
            builder = builder.resolve_to_addrs(domain, &addrs);
        }
        let client = builder
            .build()
            .map_err(|e| NetError::Transport(format!("client: {e}")))?;

        let method = reqwest::Method::from_bytes(request.method.as_bytes())
            .map_err(|_| NetError::Malformed(format!("bad method `{}`", request.method)))?;
        let mut req = client.request(method, url);
        for (name, value) in &request.headers {
            match value {
                HeaderValue::Literal(text) => {
                    // The one place a literal is read: written onto the request
                    // and marked sensitive, so the request's own `{:?}` keeps it
                    // `<redacted>` past this line too. The refusal names the
                    // header and never the value.
                    let mut value = reqwest::header::HeaderValue::from_str(text.expose())
                        .map_err(|_| {
                            NetError::Malformed(format!(
                                "header `{name}` has a value no header may carry"
                            ))
                        })?;
                    value.set_sensitive(true);
                    req = req.header(name, value);
                }
                HeaderValue::Credential(c) => {
                    // Policy resolves credentials before this crate; reaching
                    // here unresolved means the enforcement layer was skipped.
                    return Err(NetError::Malformed(format!(
                        "unresolved credential reference `{}` reached the transport",
                        c.slot
                    )));
                }
            }
        }

        let mut response = req
            .body(request.body)
            .send()
            .await
            .map_err(|e| NetError::Transport(format!("send: {e}")))?;

        let status = response.status().as_u16();
        let headers = response
            .headers()
            .iter()
            .map(|(n, v)| (n.to_string(), String::from_utf8_lossy(v.as_bytes()).into_owned()))
            .collect();

        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|e| NetError::Transport(format!("body: {e}")))?
        {
            if body.len() + chunk.len() > MAX_RESPONSE_BYTES {
                return Err(NetError::ResponseTooLarge);
            }
            body.extend_from_slice(&chunk);
        }

        tracing::debug!(
            status,
            bytes = body.len(),
            host = request.url,
            "mediated outbound request"
        );
        Ok(OutboundResponse {
            status,
            headers,
            body,
        })
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// A one-shot local HTTP server: accepts one connection, captures the raw
    /// request, sends `response`, closes. Returns (addr, captured-request).
    async fn serve_once(
        response: &'static str,
    ) -> (SocketAddr, tokio::task::JoinHandle<Vec<u8>>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut captured = Vec::new();
            let mut buf = [0u8; 4096];
            // Read until the header terminator; enough for these tests, which
            // send small bodies within the same segments.
            loop {
                let n = sock.read(&mut buf).await.unwrap();
                captured.extend_from_slice(&buf[..n]);
                if n == 0 || captured.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            sock.write_all(response.as_bytes()).await.unwrap();
            sock.shutdown().await.ok();
            captured
        });
        (addr, handle)
    }

    fn get(url: String) -> OutboundRequest {
        OutboundRequest {
            method: "GET".into(),
            url,
            headers: vec![(
                "x-test".into(),
                HeaderValue::Literal(kotton_sys::outbound::HeaderText::new("present")),
            )],
            body: Vec::new(),
        }
    }

    #[tokio::test]
    async fn a_request_round_trips_with_status_headers_and_body() {
        let (addr, captured) = serve_once(
            "HTTP/1.1 200 OK\r\ncontent-length: 5\r\nx-reply: yes\r\nconnection: close\r\n\r\nhello",
        )
        .await;
        let mediator = HttpNetMediator::dangerously_allow_local_for_tests();
        let resp = mediator
            .perform(get(format!("http://{addr}/path")))
            .await
            .expect("round trip");
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, b"hello");
        assert!(resp.headers.iter().any(|(n, v)| n == "x-reply" && v == "yes"));
        let raw = String::from_utf8_lossy(&captured.await.unwrap()).to_lowercase();
        assert!(raw.starts_with("get /path"), "got: {raw}");
        assert!(raw.contains("x-test: present"));
    }

    #[tokio::test]
    async fn local_destinations_are_refused_by_the_production_mediator() {
        // No listener needed: refusal happens before any connection.
        let mediator = HttpNetMediator::new();
        let err = mediator
            .perform(get("http://127.0.0.1:9/".into()))
            .await
            .expect_err("loopback must be refused");
        assert!(matches!(err, NetError::DestinationRefused(_)), "got: {err}");
        let err = mediator
            .perform(get("http://192.168.1.1/".into()))
            .await
            .expect_err("RFC1918 must be refused");
        assert!(matches!(err, NetError::DestinationRefused(_)), "got: {err}");
        let err = mediator
            .perform(get("http://169.254.169.254/latest/meta-data/".into()))
            .await
            .expect_err("the cloud metadata endpoint must be refused");
        assert!(matches!(err, NetError::DestinationRefused(_)), "got: {err}");
    }

    #[tokio::test]
    async fn redirects_are_returned_not_followed() {
        let (addr, _captured) = serve_once(
            "HTTP/1.1 302 Found\r\nlocation: http://127.0.0.1:1/elsewhere\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
        )
        .await;
        let mediator = HttpNetMediator::dangerously_allow_local_for_tests();
        let resp = mediator
            .perform(get(format!("http://{addr}/")))
            .await
            .expect("the 302 itself is a valid response");
        assert_eq!(resp.status, 302, "a redirect is a policy decision for the caller");
    }

    #[tokio::test]
    async fn an_unresolved_credential_reference_is_refused_at_the_transport() {
        let mediator = HttpNetMediator::dangerously_allow_local_for_tests();
        let mut req = get("http://127.0.0.1:9/".into());
        req.headers.push((
            "authorization".into(),
            HeaderValue::Credential(kotton_sys::outbound::CredentialRef::new(
                "s3-key", "Bearer {}",
            )),
        ));
        let err = mediator.perform(req).await.expect_err("must refuse");
        assert!(
            matches!(err, NetError::Malformed(ref m) if m.contains("credential")),
            "got: {err}"
        );
    }

    /// A literal no header may carry is refused before anything is sent, and
    /// the refusal names the header, never the value.
    #[tokio::test]
    async fn an_unwritable_literal_is_refused_without_its_value() {
        const SECRET: &str = "Bearer 3f9a1c7e\nx-injected: yes";
        let mediator = HttpNetMediator::dangerously_allow_local_for_tests();
        let mut req = get("http://127.0.0.1:9/".into());
        req.headers.push((
            "authorization".into(),
            HeaderValue::Literal(kotton_sys::outbound::HeaderText::new(SECRET)),
        ));
        let err = mediator.perform(req).await.expect_err("must refuse");
        let NetError::Malformed(message) = err else {
            panic!("an unwritable literal must be refused as malformed, got: {err}");
        };
        assert!(message.contains("authorization"), "{message}");
        assert!(!message.contains("3f9a1c7e"), "the value prints in {message}");
    }

    #[tokio::test]
    async fn non_http_schemes_are_not_mediated() {
        let mediator = HttpNetMediator::new();
        let err = mediator
            .perform(get("ftp://example.com/".into()))
            .await
            .expect_err("must refuse");
        assert!(matches!(err, NetError::Malformed(_)));
    }
}
