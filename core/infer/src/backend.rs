// SPDX-License-Identifier: AGPL-3.0-or-later
//! What a runtime must be able to do, and nothing about how (RFC-0085 IN1).
//!
//! ## The requirement on a backend
//!
//! Fixed by RFC-0085, and restated here because this trait is where it is
//! actually met: loads a quantised small model — the order of one to four
//! billion parameters — from a standard weights format; runs on CPU on every
//! platform the daemon builds for, with an accelerator where one exists;
//! streams tokens; is interruptible; has no network. One reference backend
//! ships; a second may be added behind this trait.
//!
//! [`StubBackend`](crate::StubBackend) meets none of the model requirements and
//! is not pretending to: it exists so the pipe, the supervision and the keyless
//! boundary have something to carry before a real runtime is chosen.
//!
//! ## Bytes, not a reference
//!
//! [`Backend::load`] takes the weight bytes. RFC-0085's sketch writes
//! `SealedObjectRef` and its prose rules the other way — *"the daemon reads the
//! weights out of the store under the unlocked context and streams the bytes to
//! `kinferd` over the pipe, so the backend never touches a path the person did
//! not open and never holds a key."* A reference would be a name only the store
//! can resolve, in a process that must not link the store.
//!
//! ## Interruption
//!
//! [`TokenStream`] is pulled rather than pushed, so stopping is dropping it.
//! There is no `cancel` to forget to call, and no half-cancelled generation for
//! the caller to reason about — RFC-0085's *"generation is cancellable from the
//! surface at any token"* becomes a property of the shape rather than a verb.
//!
//! ## Errors say what failed, never what was being processed
//!
//! IN9: *"No prompt, passage or answer appears in any log or diagnostic."* An
//! [`InferError`] crosses the pipe and may be logged by whoever receives it, so
//! no variant here carries text from a [`Context`](crate::Context) or from the
//! generated answer. A message names the stage and the model, which is what a
//! person debugging actually needs.

use crate::{Context, ModelManifest, Options};
use serde::{Deserialize, Serialize};

/// A backend's own name for a model it has loaded.
///
/// Opaque: the backend chose the number and only the backend may interpret it.
/// It is what makes [`Backend`] object-safe without an associated type — the
/// daemon holds a `Box<dyn Backend>` and the loaded weights never leave the
/// process that parsed them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ModelHandle(pub u64);

/// A loaded model: what the backend called it, and what it was told it is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Model {
    pub handle: ModelHandle,
    pub manifest: ModelManifest,
}

/// Numbers about a generation, and only numbers (RFC-0085's Metering, IN9).
///
/// *"The runtime reports tokens per second, time to first token, and model load
/// time to the surface and to diagnostics as numbers. It reports nothing else."*
/// Every field here is a count or a duration; there is nowhere to put a
/// fragment of the question even by accident.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Metering {
    /// Tokens produced.
    pub tokens: u32,
    /// Milliseconds from the request to the first token.
    pub first_token_ms: u64,
    /// Milliseconds from the request to the last token.
    pub total_ms: u64,
}

/// Tokens as the backend produces them.
///
/// An iterator rather than a channel: the caller decides the pace, and dropping
/// it is how a generation stops. `Send` so the process that owns the pipe can
/// drive it off the reactor thread.
pub struct TokenStream {
    inner: Box<dyn Iterator<Item = Result<String, InferError>> + Send>,
}

impl TokenStream {
    pub fn new<I>(tokens: I) -> Self
    where
        I: IntoIterator<Item = Result<String, InferError>>,
        I::IntoIter: Send + 'static,
    {
        Self {
            inner: Box::new(tokens.into_iter()),
        }
    }
}

impl Iterator for TokenStream {
    type Item = Result<String, InferError>;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next()
    }
}

impl std::fmt::Debug for TokenStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // No length and no peek: both would mean holding tokens here, and a
        // token held here is answer text living somewhere IN9 did not put it.
        f.write_str("TokenStream(..)")
    }
}

/// What can go wrong, said without quoting the person's data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
pub enum InferError {
    /// The handle names no model this backend has loaded.
    #[error("no model loaded under handle {0}")]
    UnknownModel(u64),
    /// The manifest asks for a format this backend cannot parse.
    #[error("backend does not support the {0} weights format")]
    UnsupportedFormat(String),
    /// The manifest asks for a kind this backend does not serve — an `embed`
    /// call against a `chat` model, or a `vision` model at all.
    #[error("backend does not support the {0} model kind")]
    UnsupportedKind(String),
    /// The weights did not parse. The reason names the stage, never the bytes.
    #[error("weights rejected: {0}")]
    Weights(String),
    /// Generation failed partway. Anything already streamed has been streamed.
    #[error("generation failed: {0}")]
    Generation(String),
}

/// One inference runtime.
///
/// `&self` throughout: a backend holds its loaded models internally and is
/// shared, because the process it runs in has exactly one of it.
pub trait Backend: Send + Sync {
    /// Parse `weights` as the manifest describes them, and keep them.
    ///
    /// This is the untrusted parse RFC-0085 built a separate process around. A
    /// panic or a crash here is a crash of a keyless process, and the daemon
    /// restarts it.
    fn load(&self, weights: &[u8], manifest: &ModelManifest) -> Result<Model, InferError>;

    /// Embed `text` with a `kind: embed` model.
    fn embed(&self, model: &Model, text: &str) -> Result<Vec<f32>, InferError>;

    /// Begin generating from the host-composed context.
    ///
    /// `Result` where RFC-0085's sketch writes a bare `TokenStream`: a model
    /// that cannot start has to be able to say so before the first token,
    /// rather than by yielding one error and stopping.
    fn generate(
        &self,
        model: &Model,
        ctx: &Context,
        opts: &Options,
    ) -> Result<TokenStream, InferError>;
}
