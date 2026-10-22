// SPDX-License-Identifier: AGPL-3.0-or-later
//! Driving one fetch cycle of a confined extension (RFC-0049; Sprint 03
//! Phase 3d).
//!
//! The loop that joins the two sides built in phases 3b and 3c: send the
//! runner a [`RunnerOp::Fetch`], then service every [`RunnerOutput::HostCall`]
//! it raises through [`ExtensionHost`] until it reports a terminal result.
//!
//! ```text
//!   daemon                                  runner (confined guest)
//!     │  Fetch { config }              ──▶    fetch(config)
//!     │                                        │ net.request-fn(...)
//!     │  ◀── HostCall { NetRequest }  ─────────┘
//!     │  ── HostReply { NetResponse } ────────▶ (guest resumes)
//!     │                                        │ quarantine.write(...)
//!     │  ◀── HostCall { QuarantineWrite } ─────┘
//!     │  ── HostReply { QuarantineWritten } ──▶
//!     │  ◀── Fetched { wrote: [...] }  ────────  (export returns)
//! ```
//!
//! Generic over the streams so the loop is tested against a scripted runner on
//! an in-memory duplex, rather than only through a spawned process.
//!
//! ## Why the call budget exists
//!
//! Phase 0's epoch deadline bounds *compute*, and the rate cap in
//! [`ExtensionNetPolicy`] bounds *network*. Neither bounds a guest that sits in
//! a loop issuing cheap quarantine writes: each one blocks on host I/O rather
//! than burning fuel, and while every individual object is size-capped, their
//! number was not. [`MAX_HOST_CALLS_PER_CYCLE`] closes that — the same
//! discipline as the other two limits, applied to the axis they left open.
//!
//! [`ExtensionNetPolicy`]: kotton_outbound::ExtensionNetPolicy

use kotton_wire::runner::{RunnerMessage, RunnerOp, RunnerOutput};
use thiserror::Error;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};

use crate::extension_host::ExtensionHost;

/// Most host calls one fetch cycle may make.
///
/// Generous for real work — a feed reader makes a handful, a calendar mirror
/// perhaps hundreds — and far below what a hostile extension would need to
/// exhaust the disk one size-capped object at a time.
pub const MAX_HOST_CALLS_PER_CYCLE: usize = 10_000;

#[derive(Debug, Error)]
pub enum FetchSessionError {
    #[error("the extension reported: {0}")]
    Extension(String),
    #[error("protocol violation: {0}")]
    Protocol(String),
    #[error("the extension exceeded {MAX_HOST_CALLS_PER_CYCLE} host calls in one cycle")]
    CallBudgetExhausted,
    #[error("i/o with the runner failed: {0}")]
    Io(String),
}

/// Run one fetch cycle and return the quarantine keys the extension wrote.
///
/// `reader` is the runner's stdout; `writer` its stdin. The caller owns the
/// process (and its kill switch): a runner that stops responding is the
/// caller's timeout to enforce, not this loop's, because only the caller can
/// actually terminate it.
pub async fn run_fetch_cycle<R, W>(
    host: &ExtensionHost,
    reader: R,
    mut writer: W,
    config: Vec<(String, String)>,
) -> Result<Vec<String>, FetchSessionError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    write_frame(
        &mut writer,
        &RunnerMessage {
            op: RunnerOp::Fetch { config },
        },
    )
    .await?;

    let mut reader = BufReader::new(reader);
    let mut calls = 0usize;
    let mut line = String::new();

    loop {
        line.clear();
        match reader.read_line(&mut line).await {
            Ok(0) => {
                return Err(FetchSessionError::Protocol(
                    "the runner closed its output before reporting a result".into(),
                ))
            }
            Ok(_) => {}
            Err(e) => return Err(FetchSessionError::Io(format!("read: {e}"))),
        }

        let frame: RunnerOutput = serde_json::from_str(line.trim())
            .map_err(|e| FetchSessionError::Protocol(format!("undecodable frame: {e}")))?;

        match frame {
            RunnerOutput::HostCall { call } => {
                calls += 1;
                if calls > MAX_HOST_CALLS_PER_CYCLE {
                    return Err(FetchSessionError::CallBudgetExhausted);
                }
                let reply = host.service(call).await;
                write_frame(
                    &mut writer,
                    &RunnerMessage {
                        op: RunnerOp::HostReply { reply },
                    },
                )
                .await?;
            }
            RunnerOutput::Fetched { wrote } => {
                tracing::info!(calls, wrote = wrote.len(), "fetch cycle complete");
                return Ok(wrote);
            }
            RunnerOutput::Error { message } => return Err(FetchSessionError::Extension(message)),
            other => {
                return Err(FetchSessionError::Protocol(format!(
                    "expected a host call or a result during a fetch, got {other:?}"
                )))
            }
        }
    }
}

async fn write_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    message: &RunnerMessage,
) -> Result<(), FetchSessionError> {
    let json = serde_json::to_string(message)
        .map_err(|e| FetchSessionError::Protocol(format!("serialize frame: {e}")))?;
    writer
        .write_all(json.as_bytes())
        .await
        .map_err(|e| FetchSessionError::Io(format!("write: {e}")))?;
    writer
        .write_all(b"\n")
        .await
        .map_err(|e| FetchSessionError::Io(format!("write: {e}")))?;
    writer
        .flush()
        .await
        .map_err(|e| FetchSessionError::Io(format!("flush: {e}")))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::quarantine::Quarantine;
    use async_trait::async_trait;
    use kotton_outbound::ExtensionNetPolicy;
    use kotton_schemas::{CapabilityGrant, CapabilityKind, CapabilitySet, CapabilityTarget};
    use kotton_store::MemoryObjectStorage;
    use kotton_sys::outbound::{
        DestinationPolicy, EndpointPattern, NetMediator, NetResult, OutboundRequest,
        OutboundResponse,
    };
    use kotton_sys::secret::{SecretsResult, SecretsStore};
    use kotton_sys::store::ObjectStorage;
    use kotton_wire::runner::{HostRequest, RunnerHostCall};
    use std::sync::Arc;

    const EXT: &str = "sh.kotton.feed-reader";

    struct OkMediator;

    #[async_trait]
    impl NetMediator for OkMediator {
        async fn perform(&self, _req: OutboundRequest) -> NetResult<OutboundResponse> {
            Ok(OutboundResponse {
                status: 200,
                headers: vec![],
                body: b"<rss><item>hello</item></rss>".to_vec(),
            })
        }
    }

    struct NoSecrets;

    impl SecretsStore for NoSecrets {
        fn get_secret(&self, _k: &str) -> SecretsResult<Option<String>> {
            Ok(None)
        }
        fn set_secret(&self, _k: &str, _v: &str) -> SecretsResult<()> {
            Ok(())
        }
        fn delete_secret(&self, _k: &str) -> SecretsResult<()> {
            Ok(())
        }
    }

    fn host() -> (ExtensionHost, Arc<dyn ObjectStorage>) {
        let store: Arc<dyn ObjectStorage> = Arc::new(MemoryObjectStorage::new());
        let target = CapabilityTarget::Quarantine {
            extension_id: EXT.to_string(),
        };
        let grants = CapabilitySet::new(vec![
            CapabilityGrant {
                kind: CapabilityKind::Write,
                target: target.clone(),
            },
            CapabilityGrant {
                kind: CapabilityKind::Read,
                target,
            },
        ]);
        let net = ExtensionNetPolicy::new(
            EXT,
            DestinationPolicy::declared(vec![EndpointPattern::parse("example.com").unwrap()]),
            Arc::new(OkMediator),
            Arc::new(NoSecrets),
        );
        (
            ExtensionHost::new(net, Quarantine::new(EXT, grants, store.clone())),
            store,
        )
    }

    /// A scripted runner: emits `frames` in order, reading one reply between
    /// each. Returns the replies it received.
    async fn scripted_runner(
        frames: Vec<RunnerOutput>,
        stdout: tokio::io::DuplexStream,
    ) -> Vec<RunnerOp> {
        let (rx, mut tx) = tokio::io::split(stdout);
        let mut reader = BufReader::new(rx);
        let mut replies = Vec::new();

        // The daemon's opening Fetch frame.
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();
        replies.push(
            serde_json::from_str::<RunnerMessage>(line.trim())
                .unwrap()
                .op,
        );

        for frame in frames {
            let json = serde_json::to_string(&frame).unwrap();
            tx.write_all(json.as_bytes()).await.unwrap();
            tx.write_all(b"\n").await.unwrap();
            tx.flush().await.unwrap();
            // Terminal frames get no reply.
            if matches!(frame, RunnerOutput::HostCall { .. }) {
                line.clear();
                if reader.read_line(&mut line).await.unwrap_or(0) == 0 {
                    break;
                }
                replies.push(
                    serde_json::from_str::<RunnerMessage>(line.trim())
                        .unwrap()
                        .op,
                );
            }
        }
        replies
    }

    fn net_call(url: &str) -> RunnerOutput {
        RunnerOutput::HostCall {
            call: RunnerHostCall::NetRequest {
                request: HostRequest {
                    method: "GET".into(),
                    url: url.into(),
                    headers: vec![],
                    body: vec![],
                },
            },
        }
    }

    fn write_call(key: &str) -> RunnerOutput {
        RunnerOutput::HostCall {
            call: RunnerHostCall::QuarantineWrite {
                key: key.into(),
                content: b"<rss/>".to_vec(),
            },
        }
    }

    /// The whole point: a cycle fetches, writes, and reports what landed.
    #[tokio::test]
    async fn a_cycle_fetches_writes_and_reports_what_landed() {
        let (host, store) = host();
        let (daemon_side, runner_side) = tokio::io::duplex(64 * 1024);
        let (d_rx, d_tx) = tokio::io::split(daemon_side);

        let runner = tokio::spawn(scripted_runner(
            vec![
                net_call("https://example.com/feed.xml"),
                write_call("feed.xml"),
                RunnerOutput::Fetched {
                    wrote: vec!["feed.xml".into()],
                },
            ],
            runner_side,
        ));

        let wrote = run_fetch_cycle(
            &host,
            d_rx,
            d_tx,
            vec![("url".into(), "https://example.com/feed.xml".into())],
        )
        .await
        .expect("cycle completes");

        assert_eq!(wrote, vec!["feed.xml".to_string()]);
        assert_eq!(host.keys_written(), vec!["feed.xml".to_string()]);

        let ops = runner.await.unwrap();
        assert!(
            matches!(ops[0], RunnerOp::Fetch { .. }),
            "the cycle opens with a Fetch carrying the user's config"
        );
        assert!(matches!(ops[1], RunnerOp::HostReply { .. }));

        // The content really landed in the extension's namespace.
        let listed = store.list(std::path::Path::new("")).await.unwrap();
        assert!(listed.iter().any(|e| e
            .key
            .starts_with(&format!("system/extensions/{EXT}/quarantine/"))));
    }

    /// A refusal reaches the guest and the cycle continues — the extension may
    /// handle it. What it cannot do is reach the destination.
    #[tokio::test]
    async fn a_refused_destination_does_not_abort_the_cycle() {
        let (host, _store) = host();
        let (daemon_side, runner_side) = tokio::io::duplex(64 * 1024);
        let (d_rx, d_tx) = tokio::io::split(daemon_side);

        let runner = tokio::spawn(scripted_runner(
            vec![
                net_call("https://evil.test/collect"),
                RunnerOutput::Fetched { wrote: vec![] },
            ],
            runner_side,
        ));

        let wrote = run_fetch_cycle(&host, d_rx, d_tx, vec![])
            .await
            .expect("the cycle completes even though the request was refused");
        assert!(wrote.is_empty());

        let ops = runner.await.unwrap();
        let RunnerOp::HostReply { reply } = &ops[1] else {
            panic!("expected a reply, got {:?}", ops[1]);
        };
        let serialized = serde_json::to_string(reply).unwrap();
        assert!(
            serialized.contains("evil.test") && serialized.contains("net_error"),
            "the guest must see a typed refusal: {serialized}"
        );
    }

    #[tokio::test]
    async fn an_extension_error_surfaces_to_the_caller() {
        let (host, _store) = host();
        let (daemon_side, runner_side) = tokio::io::duplex(64 * 1024);
        let (d_rx, d_tx) = tokio::io::split(daemon_side);

        tokio::spawn(scripted_runner(
            vec![RunnerOutput::Error {
                message: "feed parse failed".into(),
            }],
            runner_side,
        ));

        let err = run_fetch_cycle(&host, d_rx, d_tx, vec![])
            .await
            .expect_err("an extension error is not success");
        assert!(matches!(err, FetchSessionError::Extension(ref m) if m.contains("feed parse")));
    }

    /// A guest that dies mid-cycle is a failed cycle, not a hang.
    #[tokio::test]
    async fn a_runner_that_vanishes_is_an_error_not_a_hang() {
        let (host, _store) = host();
        let (daemon_side, runner_side) = tokio::io::duplex(1024);
        let (d_rx, d_tx) = tokio::io::split(daemon_side);
        drop(runner_side);

        let err = run_fetch_cycle(&host, d_rx, d_tx, vec![])
            .await
            .expect_err("a vanished runner must surface");
        assert!(
            matches!(
                err,
                FetchSessionError::Protocol(_) | FetchSessionError::Io(_)
            ),
            "got: {err}"
        );
    }

    /// The axis the epoch deadline and the network rate cap left open: a guest
    /// looping on cheap host I/O. Bounded, and bounded *before* the writes land.
    #[tokio::test]
    async fn a_guest_looping_on_host_calls_is_cut_off() {
        let (host, _store) = host();
        let (daemon_side, runner_side) = tokio::io::duplex(1024 * 1024);
        let (d_rx, d_tx) = tokio::io::split(daemon_side);

        // Never terminates: always another write, never a Fetched.
        tokio::spawn(async move {
            let (rx, mut tx) = tokio::io::split(runner_side);
            let mut reader = BufReader::new(rx);
            let mut line = String::new();
            let _ = reader.read_line(&mut line).await; // the Fetch frame
            loop {
                let json = serde_json::to_string(&write_call("spam.bin")).unwrap();
                if tx.write_all(json.as_bytes()).await.is_err() {
                    break;
                }
                if tx.write_all(b"\n").await.is_err() {
                    break;
                }
                let _ = tx.flush().await;
                line.clear();
                if reader.read_line(&mut line).await.unwrap_or(0) == 0 {
                    break;
                }
            }
        });

        let err = run_fetch_cycle(&host, d_rx, d_tx, vec![])
            .await
            .expect_err("an unbounded host-call loop must be cut off");
        assert!(
            matches!(err, FetchSessionError::CallBudgetExhausted),
            "got: {err}"
        );
    }
}
