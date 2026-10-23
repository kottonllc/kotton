// SPDX-License-Identifier: AGPL-3.0-or-later
//! kuserd's end of the inference channel to `kinferd`.
//!
//! The daemon holds the keys and `kinferd` holds the weights parser, and this is
//! the pipe between them. It is made by the spawn: `supervise_kinferd` calls
//! [`InferProxy::attach`] with the child's standard streams before the child can
//! speak, and [`InferProxy::detach`] when it exits. There is no path, so there is
//! nothing else that could be on the far end.
//!
//! ## Why no reader task, where the surface has one
//!
//! [`crate::surface_proxy::SurfaceProxy`] runs a reader task and a pending slot
//! because `kuid` raises events of its own: replies and events share one
//! descriptor, so something has to route by frame kind. `kinferd` raises
//! nothing. It answers, in order, and the answer to the one outstanding request
//! is the next frame — so both halves live under one lock and the reply is read
//! where the request was written. A reader task here would be a second owner of
//! the descriptor with nothing to own.
//!
//! ## Why a missing runtime is an error, where a missing compositor is not
//!
//! A dropped surface patch is a frame nobody drew; the app redraws. A dropped
//! question is a person waiting for an answer that is never coming, with nothing
//! to tell them why. So every method here returns the failure rather than
//! warning and returning `Ok`.
//!
//! ## What does not cross
//!
//! Weights and plaintext passages go out; tokens come back. **No key material
//! crosses in either direction** — `kinferd` is handed bytes the daemon has
//! already read under the unlocked context, never a path, a store handle or a key.
//! `key-reach-check` holds that from `core/context`'s side and
//! `cargo xtask infer-check` from the sidecar's.
//!
//! ## Where a stored manifest becomes the backend's
//!
//! A model's manifest is the protocol's: `kotton_schemas::ModelManifest`, the
//! body of a `sh.kotton.model` record, which the wire, the device daemon and the
//! client carry without linking the inference runtime. `kotton-infer` keeps its
//! own, because `infer-check` holds that crate to serde and thiserror. This
//! daemon is the one process that links both, so its tests are where the two are
//! held to one shape. They convert each way, each side destructured with no `..`
//! and each side's enums matched exhaustively where they are the input, so a
//! field or a variant added to either side and not the other fails them to
//! compile.

use kotton_infer::{Context, Metering, ModelHandle, ModelManifest, Options};
use kotton_infer::{InferRequest, InferResponse, MAX_LOAD_CHUNK};
use kotton_ipc::{read_frame, write_frame, FrameRead, Refusal};
use std::io;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::Mutex;

/// One live pair: the half kuserd writes on, and the half it reads.
///
/// Boxed rather than typed as `ChildStdin`/`ChildStdout` so the round-trip test
/// can drive the real methods over a `duplex` without spawning a process. The
/// security property is unchanged by this: it comes from the descriptors being
/// *handed to the child at spawn*, not from their Rust type.
struct Channel {
    write: Box<dyn AsyncWrite + Unpin + Send>,
    read: Box<dyn AsyncRead + Unpin + Send>,
}

/// kuserd's handle on the inference channel.
///
/// Empty until `supervise_kinferd` attaches a live pair, and empty again once
/// the child exits.
#[derive(Default)]
pub struct InferProxy {
    /// One conversation at a time. The mutex is what makes "the next frame is
    /// my reply" true, so it is held across the whole request, streaming
    /// included.
    conn: Mutex<Option<Channel>>,
    /// The last frame **this end** refused, until the supervisor takes it.
    ///
    /// This is the half of the refusal the child cannot tell anyone about, so
    /// it is kept here: refusing drops the channel, which closes the child's
    /// stdin, so the child reads end-of-stream and exits **0** — and an exit of
    /// 0 is how a sidecar says *I was asked to stop*. Left there, supervision
    /// would end with `SidecarState.failed` still `None`, and a parser made to
    /// emit one bad byte on stdout would switch the assistant off for the
    /// daemon's lifetime with nothing written down. That is the direction a
    /// compromised runtime actually controls, and a refused frame must not read
    /// as a clean exit.
    ///
    /// A `std::sync::Mutex` rather than the async one beside it because it is
    /// never held across an await: set under the conversation lock, taken by the
    /// supervisor between a `wait` and a respawn.
    refused: std::sync::Mutex<Option<Refusal>>,
}

impl InferProxy {
    pub fn new() -> Self {
        Self::default()
    }

    /// Take ownership of kuserd's end of a freshly created pair.
    ///
    /// Called before the spawned child is awaited, so a request racing its
    /// startup finds a channel rather than a hole.
    pub async fn attach<W, R>(&self, write: W, read: R)
    where
        W: AsyncWrite + Unpin + Send + 'static,
        R: AsyncRead + Unpin + Send + 'static,
    {
        let mut guard = self.conn.lock().await;
        *guard = Some(Channel {
            write: Box::new(write),
            read: Box::new(read),
        });
    }

    /// Drop our end, because the child that held the other one is gone.
    pub async fn detach(&self) {
        let mut guard = self.conn.lock().await;
        *guard = None;
    }

    /// Take the last frame this end refused, if it refused one.
    ///
    /// Called by `supervise_kinferd` after the child exits and before it
    /// respawns. **Taking is the point**: the refusal belongs to the run that
    /// just ended, and a refusal left behind would be read as an explanation for
    /// the next child's exit as well.
    ///
    /// The supervisor needs this because the child's exit code cannot carry it.
    /// A child whose stdin closed exits 0 whatever the daemon's reason for
    /// closing it was, so "was this a shutdown or a protocol break?" is a
    /// question only this end can answer.
    pub fn take_refusal(&self) -> Option<Refusal> {
        self.refused.lock().ok().and_then(|mut slot| slot.take())
    }

    /// Whether a runtime is attached. The answer a surface needs before it
    /// offers to answer a question.
    pub async fn is_attached(&self) -> bool {
        self.conn.lock().await.is_some()
    }

    /// Stream a model's weights across and have the runtime parse them.
    ///
    /// The caller has already read these bytes out of the store under the
    /// unlocked context; what crosses is plaintext weights and a manifest.
    pub async fn load(&self, manifest: &ModelManifest, weights: &[u8]) -> io::Result<ModelHandle> {
        let mut guard = self.conn.lock().await;

        let mut frames = vec![InferRequest::LoadBegin {
            manifest: Box::new(manifest.clone()),
        }];
        for chunk in weights.chunks(MAX_LOAD_CHUNK) {
            frames.push(InferRequest::LoadChunk {
                bytes: chunk.to_vec(),
            });
        }
        frames.push(InferRequest::LoadEnd);
        for frame in &frames {
            send(&mut guard, frame).await?;
        }

        match receive(&mut guard, &self.refused).await? {
            InferResponse::Loaded { model } => Ok(model),
            InferResponse::Failed { error } => Err(io::Error::other(error.to_string())),
            other => Err(unexpected(&other)),
        }
    }

    /// Ask the loaded model the host-composed question, one token at a time.
    ///
    /// `on_token` is called with each token exactly as the runtime produced it;
    /// concatenating them gives the answer byte for byte. Citations are resolved
    /// by the caller against the labels *it* issued — this function never looks
    /// inside a token, which is the mechanical half of citing only what it labelled.
    pub async fn generate<F>(
        &self,
        model: ModelHandle,
        context: &Context,
        options: &Options,
        mut on_token: F,
    ) -> io::Result<Metering>
    where
        F: FnMut(&str),
    {
        let mut guard = self.conn.lock().await;

        send(
            &mut guard,
            &InferRequest::Generate {
                model,
                context: Box::new(context.clone()),
                options: options.clone(),
            },
        )
        .await?;

        loop {
            match receive(&mut guard, &self.refused).await? {
                InferResponse::Token { text } => on_token(&text),
                InferResponse::Done { metering } => return Ok(metering),
                InferResponse::Failed { error } => return Err(io::Error::other(error.to_string())),
                other => return Err(unexpected(&other)),
            }
        }
    }

    /// Embed one text with a loaded `kind: embed` model.
    pub async fn embed(&self, model: ModelHandle, text: &str) -> io::Result<Vec<f32>> {
        let mut guard = self.conn.lock().await;

        send(
            &mut guard,
            &InferRequest::Embed {
                model,
                text: text.to_string(),
            },
        )
        .await?;

        match receive(&mut guard, &self.refused).await? {
            InferResponse::Embedding { vector } => Ok(vector),
            InferResponse::Failed { error } => Err(io::Error::other(error.to_string())),
            other => Err(unexpected(&other)),
        }
    }
}

/// Write one frame, and drop the channel if the write fails.
///
/// The dropping is the point. A pipe that refused a write is a pipe whose far
/// end is gone, and leaving it attached means the next caller writes into it
/// too — the supervisor is already restarting the child, and the clear "no
/// runtime is attached" failure is a better answer than a second broken pipe.
///
/// This was not the first version. The first returned the write error with `?`
/// and left the dead channel in place, and the test for a runtime that
/// disappears mid-answer is what said so.
async fn send(guard: &mut Option<Channel>, request: &InferRequest) -> io::Result<()> {
    let result = match guard.as_mut() {
        Some(channel) => write_frame(&mut channel.write, request).await,
        None => return Err(no_runtime()),
    };
    if let Err(e) = result {
        *guard = None;
        return Err(e);
    }
    Ok(())
}

/// Read the next frame, and drop the channel if there is not one.
///
/// The two ways there is not one are two errors, not one. A runtime that
/// **closed** is a runtime the supervisor is already restarting; a runtime that
/// sent something this end **refuses** is the case the sidecar's own header
/// names — a stray line on stdout from a future backend — and reporting it as a
/// close hides the only evidence that it happened. Either way the channel is
/// dropped: the frame boundary is lost, so nothing further on it is readable.
///
/// A refusal is also **left where the supervisor will find it** (`refused`), and
/// that is not bookkeeping. Dropping the channel closes the child's stdin, so
/// the child reads end-of-stream and exits 0 — the one exit code that means *I
/// was asked to stop*. Without this the caller got a clear error and the
/// supervisor got a clean shutdown for the same event, and the supervisor is the
/// one that decides whether inference continues.
async fn receive(
    guard: &mut Option<Channel>,
    refused: &std::sync::Mutex<Option<Refusal>>,
) -> io::Result<InferResponse> {
    let frame = match guard.as_mut() {
        Some(channel) => read_frame::<InferResponse, _>(&mut channel.read).await,
        None => return Err(no_runtime()),
    };
    match frame {
        FrameRead::Frame(response) => Ok(response),
        FrameRead::EndOfStream => {
            *guard = None;
            Err(closed())
        }
        FrameRead::Refused(refusal) => {
            tracing::error!(
                %refusal,
                "InferProxy: the inference runtime sent a frame this end refuses"
            );
            if let Ok(mut slot) = refused.lock() {
                *slot = Some(refusal.clone());
            }
            *guard = None;
            Err(refusal.into())
        }
    }
}

fn no_runtime() -> io::Error {
    io::Error::other("no inference runtime is attached")
}

fn closed() -> io::Error {
    io::Error::other("the inference channel closed")
}

/// A frame that is not an answer to what was asked. Names the variant and not
/// its contents: a `Token`'s text is answer text, and answer text is kept out
/// of anything a caller might log.
fn unexpected(response: &InferResponse) -> io::Error {
    let variant = match response {
        InferResponse::Loaded { .. } => "Loaded",
        InferResponse::Token { .. } => "Token",
        InferResponse::Done { .. } => "Done",
        InferResponse::Embedding { .. } => "Embedding",
        InferResponse::Failed { .. } => "Failed",
    };
    io::Error::other(format!(
        "unexpected {variant} frame from the inference runtime"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use kotton_infer::{Origin, Passage, Provenance};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// The backend's manifest for a stored one: the protocol's type, as `kinferd`'s
    /// channel names it.
    ///
    /// Field for field, with no `..` on either side and an exhaustive match on the
    /// protocol's enums, so a field on either side, or a variant on the protocol's,
    /// that the other lacks fails the tests to compile; [`stored_manifest`] is the
    /// same in the other direction, for a variant on the backend's. Test-only: no
    /// path of the daemon hands a stored model to the backend yet, and the one
    /// that does starts from this.
    fn backend_manifest(stored: &kotton_schemas::ModelManifest) -> ModelManifest {
        let kotton_schemas::ModelManifest {
            name,
            version,
            weights,
            format,
            kind,
            parameters,
            quantisation,
            size,
            context_window,
            template,
            licence: kotton_schemas::Licence { spdx, text_hash },
            publisher,
        } = stored.clone();
        ModelManifest {
            name,
            version,
            weights,
            format: match format {
                kotton_schemas::ModelFormat::Gguf => kotton_infer::ModelFormat::Gguf,
                kotton_schemas::ModelFormat::Safetensors => kotton_infer::ModelFormat::Safetensors,
            },
            kind: match kind {
                kotton_schemas::ModelKind::Chat => kotton_infer::ModelKind::Chat,
                kotton_schemas::ModelKind::Embed => kotton_infer::ModelKind::Embed,
                kotton_schemas::ModelKind::Vision => kotton_infer::ModelKind::Vision,
            },
            parameters,
            quantisation,
            size,
            context_window,
            template,
            licence: kotton_infer::Licence { spdx, text_hash },
            publisher,
        }
    }

    /// The stored manifest for a backend's: [`backend_manifest`] in reverse.
    ///
    /// Here the backend's enums are the input, matched exhaustively, so a variant
    /// added to `kotton_infer::ModelKind` or `kotton_infer::ModelFormat` and not to
    /// the protocol's fails the tests to compile: an enum that appears only as an
    /// output value holds nothing.
    fn stored_manifest(backend: &ModelManifest) -> kotton_schemas::ModelManifest {
        let ModelManifest {
            name,
            version,
            weights,
            format,
            kind,
            parameters,
            quantisation,
            size,
            context_window,
            template,
            licence: kotton_infer::Licence { spdx, text_hash },
            publisher,
        } = backend.clone();
        kotton_schemas::ModelManifest {
            name,
            version,
            weights,
            format: match format {
                kotton_infer::ModelFormat::Gguf => kotton_schemas::ModelFormat::Gguf,
                kotton_infer::ModelFormat::Safetensors => kotton_schemas::ModelFormat::Safetensors,
            },
            kind: match kind {
                kotton_infer::ModelKind::Chat => kotton_schemas::ModelKind::Chat,
                kotton_infer::ModelKind::Embed => kotton_schemas::ModelKind::Embed,
                kotton_infer::ModelKind::Vision => kotton_schemas::ModelKind::Vision,
            },
            parameters,
            quantisation,
            size,
            context_window,
            template,
            licence: kotton_schemas::Licence { spdx, text_hash },
            publisher,
        }
    }

    fn context() -> Context {
        Context {
            question: "when was the boiler serviced?".to_string(),
            passages: vec![Passage {
                reference: "record://kotton/msg/1".to_string(),
                provenance: Provenance {
                    origin: Origin::Import,
                    from: None,
                    at: "2026-09-15T09:00:00Z".to_string(),
                },
                text: "the boiler was serviced in March".to_string(),
            }],
            template: "{question}".to_string(),
        }
    }

    /// The daemon's half of the round trip: the question goes out on the pipe,
    /// the tokens come back in order, and the terminator is what ends the wait.
    ///
    /// The far end here answers without deserialising — deliberately. A test
    /// double that accepted `InferRequest` would be a second acceptor of that
    /// type, which is exactly what `channel-check` forbids and what it could not
    /// tell apart from a real one.
    #[tokio::test]
    async fn a_generate_round_trips_through_the_proxy() {
        let (mut runtime_end, daemon_write) = tokio::io::duplex(64 * 1024);
        let (daemon_read, mut runtime_answers) = tokio::io::duplex(64 * 1024);

        // Queue the answer before asking, which a buffered pair allows and which
        // keeps this test free of a second task.
        for text in ["You ", "asked: ", "when was the boiler serviced?"] {
            write_frame(
                &mut runtime_answers,
                &InferResponse::Token {
                    text: text.to_string(),
                },
            )
            .await
            .expect("token queued");
        }
        write_frame(
            &mut runtime_answers,
            &InferResponse::Done {
                metering: Metering {
                    tokens: 3,
                    first_token_ms: 1,
                    total_ms: 2,
                },
            },
        )
        .await
        .expect("terminator queued");

        let proxy = InferProxy::new();
        proxy.attach(daemon_write, daemon_read).await;
        assert!(proxy.is_attached().await);

        let mut answer = String::new();
        let metering = proxy
            .generate(ModelHandle(1), &context(), &Options::default(), |t| {
                answer.push_str(t)
            })
            .await
            .expect("the runtime answers");

        assert_eq!(answer, "You asked: when was the boiler serviced?");
        assert_eq!(metering.tokens, 3);

        // The question really crossed: the frame the proxy wrote carries the
        // person's words verbatim.
        let mut sent = vec![0u8; 4096];
        let n = runtime_end
            .read(&mut sent)
            .await
            .expect("the request crossed");
        let sent = String::from_utf8_lossy(&sent[..n]).to_string();
        assert!(
            sent.contains("when was the boiler serviced?"),
            "sent: {sent}"
        );
        assert!(sent.contains("record://kotton/msg/1"), "sent: {sent}");
    }

    /// A question asked with no runtime attached fails loudly. It is not a
    /// surface patch: there is a person waiting for this one.
    #[tokio::test]
    async fn a_question_with_no_runtime_is_an_error_not_a_drop() {
        let proxy = InferProxy::new();
        assert!(!proxy.is_attached().await);
        let err = proxy
            .generate(ModelHandle(1), &context(), &Options::default(), |_| {})
            .await
            .expect_err("no runtime is a failure");
        assert!(err.to_string().contains("no inference runtime"));
    }

    /// A runtime that goes away mid-answer surfaces as a failure and leaves no
    /// dead channel behind for the next caller to write into.
    #[tokio::test]
    async fn a_channel_that_closes_mid_answer_is_dropped() {
        let (runtime_end, daemon_write) = tokio::io::duplex(1024);
        let (daemon_read, runtime_answers) = tokio::io::duplex(1024);
        drop(runtime_answers);
        drop(runtime_end);

        let proxy = InferProxy::new();
        proxy.attach(daemon_write, daemon_read).await;
        let err = proxy
            .generate(ModelHandle(1), &context(), &Options::default(), |_| {})
            .await
            .expect_err("a closed channel is a failure");
        assert!(err.to_string().contains("closed") || err.kind() == io::ErrorKind::BrokenPipe);
        assert!(!proxy.is_attached().await);
    }

    /// A refusal on this end is **left for the supervisor**, because the child's
    /// exit code cannot carry it.
    ///
    /// The channel is dropped either way, and a caller that only watched its own
    /// error could not tell this apart from a runtime that closed. The
    /// supervisor can, and it is the one that decides whether inference
    /// continues.
    #[tokio::test]
    async fn a_refusal_on_this_end_is_recorded_for_the_supervisor() {
        // Both ends generously sized, and `_runtime_end` *bound* rather than
        // dropped: the request has to fit in the buffer, because nothing is
        // reading the far side and a full pipe would hang this test instead of
        // failing it.
        let (_runtime_end, daemon_write) = tokio::io::duplex(64 * 1024);
        let (daemon_read, mut runtime_answers) = tokio::io::duplex(8 * 1024);

        // Well-formed framing, well-formed JSON, and not an `InferResponse` —
        // the shape a stray line from a future backend has.
        let junk = br#"{"NotAVariant":{}}"#;
        let mut framed = (junk.len() as u32).to_le_bytes().to_vec();
        framed.extend_from_slice(junk);
        runtime_answers
            .write_all(&framed)
            .await
            .expect("the junk frame crosses");

        let proxy = InferProxy::new();
        proxy.attach(daemon_write, daemon_read).await;
        assert!(
            proxy.take_refusal().is_none(),
            "nothing has been refused yet"
        );

        let err = proxy
            .generate(ModelHandle(1), &context(), &Options::default(), |_| {})
            .await
            .expect_err("a frame this end refuses is a failure");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(!proxy.is_attached().await, "the channel is dropped");

        let refusal = proxy
            .take_refusal()
            .expect("the refusal is left where the supervisor looks");
        assert!(
            refusal.to_string().contains("undecodable"),
            "it has to name the cause: {refusal}"
        );
        // Taken, not read: the next child's exit must not inherit it.
        assert!(proxy.take_refusal().is_none(), "a refusal is taken once");
    }

    /// The stored manifest and the backend's are one shape: every field crosses
    /// [`backend_manifest`] unchanged and back through [`stored_manifest`], and the
    /// JSON either serialises to is the same record body, signed or not, for every
    /// kind and format.
    #[test]
    fn a_stored_manifest_becomes_the_backends_unchanged() {
        use kotton_schemas::{Licence, ModelFormat, ModelKind};
        for (format, kind, publisher) in [
            (ModelFormat::Gguf, ModelKind::Chat, None),
            (ModelFormat::Safetensors, ModelKind::Embed, Some("sig".to_string())),
            (ModelFormat::Gguf, ModelKind::Vision, None),
        ] {
            let stored = kotton_schemas::ModelManifest {
                name: "fixture".to_string(),
                version: "1".to_string(),
                weights: "ab".repeat(32),
                format,
                kind,
                parameters: 7,
                quantisation: "Q4_K_M".to_string(),
                size: 9,
                context_window: 4096,
                template: "{question}".to_string(),
                licence: Licence { spdx: "Apache-2.0".to_string(), text_hash: "cd".repeat(32) },
                publisher,
            };
            let backend = backend_manifest(&stored);
            assert_eq!(
                serde_json::to_value(&backend).unwrap(),
                serde_json::to_value(&stored).unwrap(),
                "{kind:?}/{format:?}"
            );
            assert_eq!(stored_manifest(&backend), stored, "{kind:?}/{format:?} back");
        }
    }
}
