// SPDX-License-Identifier: AGPL-3.0-or-later
//! A backend that generates by echoing a fixture (RFC-0085, the runtime step).
//!
//! It exists so that *the pipe, the supervision and the keyless boundary are
//! testable before any real model*. It is not a model, it is not a fallback, and
//! it must never become one: it answers the question "did the context reach the
//! runtime and did the tokens come back?" and no other question.
//!
//! ## Why it echoes the **weights**
//!
//! The weight bytes are the fixture — this backend's "format" is UTF-8 text —
//! so the whole load path is exercised by the thing that makes the answer. A
//! stub with a hard-coded answer would pass while the bytes were never
//! delivered, which is precisely the failure the load path is here to rule out.
//!
//! ## Why it substitutes the question
//!
//! A fixture may contain `{question}` and `{passages}`. Substituting them makes
//! the round trip *observable*: an answer containing the person's words can only
//! have been produced downstream of a [`Context`] that crossed the channel.
//! Nothing else about the context reaches the output, so a test asserting on the
//! answer is asserting on delivery rather than on a model's behaviour.

use crate::{
    Backend, Context, InferError, Model, ModelHandle, ModelKind, ModelManifest, Options,
    TokenStream,
};
use std::collections::HashMap;
use std::sync::Mutex;

/// The fixture a caller gets by asking for nothing in particular.
///
/// Written as an answer that cites, because every consumer downstream of this
/// crate is being built against IN6's citation rule and wants something with a
/// `[1]` in it to resolve.
pub const FIXTURE: &str = "You asked: {question} The passages say so. {passages}";

/// The one in-tree [`Backend`]: it loads UTF-8 and echoes it.
#[derive(Default)]
pub struct StubBackend {
    loaded: Mutex<HashMap<u64, String>>,
    next: Mutex<u64>,
}

impl StubBackend {
    pub fn new() -> Self {
        Self::default()
    }

    /// The fixture a loaded handle holds, for a test that wants to check the
    /// bytes arrived intact rather than inferring it from an answer.
    pub fn fixture_of(&self, handle: ModelHandle) -> Option<String> {
        self.loaded.lock().ok()?.get(&handle.0).cloned()
    }

    fn fixture_for(&self, model: &Model) -> Result<String, InferError> {
        self.loaded
            .lock()
            .map_err(|_| InferError::Generation("backend state poisoned".to_string()))?
            .get(&model.handle.0)
            .cloned()
            .ok_or(InferError::UnknownModel(model.handle.0))
    }
}

impl Backend for StubBackend {
    fn load(&self, weights: &[u8], manifest: &ModelManifest) -> Result<Model, InferError> {
        if manifest.kind == ModelKind::Vision {
            return Err(InferError::UnsupportedKind("vision".to_string()));
        }
        // The one real parse this backend does, and the one real refusal: bytes
        // that are not the format it claims to read are rejected before they are
        // kept, which is the shape a GGUF loader's refusal will have.
        let fixture = std::str::from_utf8(weights)
            .map_err(|_| InferError::Weights("fixture weights are not UTF-8".to_string()))?
            .to_string();

        let mut next = self
            .next
            .lock()
            .map_err(|_| InferError::Weights("backend state poisoned".to_string()))?;
        *next += 1;
        let handle = ModelHandle(*next);
        drop(next);

        self.loaded
            .lock()
            .map_err(|_| InferError::Weights("backend state poisoned".to_string()))?
            .insert(handle.0, fixture);

        Ok(Model {
            handle,
            manifest: manifest.clone(),
        })
    }

    fn embed(&self, model: &Model, text: &str) -> Result<Vec<f32>, InferError> {
        if model.manifest.kind != ModelKind::Embed {
            return Err(InferError::UnsupportedKind(format!(
                "{:?} model asked to embed",
                model.manifest.kind
            )));
        }
        // Deterministic and meaningless: equal texts give equal vectors and
        // nothing else holds. An index built on these is a test of the index's
        // plumbing, never of retrieval quality.
        let _ = self.fixture_for(model)?;
        let mut vector = vec![0.0f32; 8];
        let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
        for byte in text.as_bytes() {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x100_0000_01b3);
            let slot = (hash % 8) as usize;
            vector[slot] += 1.0;
        }
        Ok(vector)
    }

    fn generate(
        &self,
        model: &Model,
        ctx: &Context,
        opts: &Options,
    ) -> Result<TokenStream, InferError> {
        if model.manifest.kind != ModelKind::Chat {
            return Err(InferError::UnsupportedKind(format!(
                "{:?} model asked to generate",
                model.manifest.kind
            )));
        }
        let fixture = self.fixture_for(model)?;

        let labels: Vec<String> = (0..ctx.passages.len()).map(Context::label_of).collect();
        let answer = fixture
            .replace("{question}", &ctx.question)
            .replace("{passages}", &labels.join(" "));

        // Tokens with their trailing space, so concatenating the stream gives
        // the answer back byte for byte. A consumer that joins tokens with a
        // space of its own is a consumer that will mangle a real tokeniser's
        // output, and this is the cheapest place to stop it learning that habit.
        let mut tokens: Vec<Result<String, InferError>> = Vec::new();
        let mut rest = answer.as_str();
        while !rest.is_empty() {
            match rest.find(' ') {
                Some(at) => {
                    tokens.push(Ok(rest[..=at].to_string()));
                    rest = &rest[at + 1..];
                }
                None => {
                    tokens.push(Ok(rest.to_string()));
                    break;
                }
            }
        }
        tokens.truncate(opts.max_tokens as usize);

        Ok(TokenStream::new(tokens))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Licence, ModelFormat, Origin, Passage, Provenance};

    fn manifest(kind: ModelKind) -> ModelManifest {
        ModelManifest {
            name: "fixture".to_string(),
            version: "0".to_string(),
            weights: "0000".to_string(),
            format: ModelFormat::Gguf,
            kind,
            parameters: 0,
            quantisation: "none".to_string(),
            size: 0,
            context_window: 4096,
            template: "{question}".to_string(),
            licence: Licence {
                spdx: "Apache-2.0".to_string(),
                text_hash: "0000".to_string(),
            },
            publisher: None,
        }
    }

    fn context(question: &str) -> Context {
        Context {
            question: question.to_string(),
            passages: vec![Passage {
                reference: "record://kotton/msg/1".to_string(),
                provenance: Provenance {
                    origin: Origin::Import,
                    from: Some("did:key:zAlice".to_string()),
                    at: "2026-09-15T09:00:00Z".to_string(),
                },
                text: "the boiler was serviced in March".to_string(),
            }],
            template: "{question}".to_string(),
        }
    }

    /// The round trip the runtime step asks for, at the trait: bytes in, a model
    /// back, a host-composed context in, the person's own words out.
    #[test]
    fn a_generate_round_trips_through_the_stub_backend() {
        let backend = StubBackend::new();
        let model = backend
            .load(FIXTURE.as_bytes(), &manifest(ModelKind::Chat))
            .expect("fixture weights load");

        let ctx = context("when was the boiler serviced?");
        let stream = backend
            .generate(&model, &ctx, &Options::default())
            .expect("generation starts");

        let answer: String = stream.map(|t| t.expect("token")).collect();
        assert_eq!(
            answer,
            "You asked: when was the boiler serviced? The passages say so. [1]"
        );
        // The label in the answer is one the host issued, so it resolves.
        assert_eq!(
            ctx.passage_for_label("[1]").map(|p| p.reference.as_str()),
            Some("record://kotton/msg/1")
        );
    }

    /// `max_tokens` is a ceiling, not a suggestion — the budget belongs to the
    /// host and the backend may not spend past it.
    #[test]
    fn generation_stops_at_the_caller_s_token_ceiling() {
        let backend = StubBackend::new();
        let model = backend
            .load(FIXTURE.as_bytes(), &manifest(ModelKind::Chat))
            .expect("fixture weights load");
        let opts = Options {
            max_tokens: 2,
            ..Options::default()
        };
        let tokens: Vec<String> = backend
            .generate(&model, &context("when?"), &opts)
            .expect("generation starts")
            .map(|t| t.expect("token"))
            .collect();
        assert_eq!(tokens, vec!["You ".to_string(), "asked: ".to_string()]);
    }

    /// The loader refuses bytes that are not what the manifest promised, and
    /// says so without quoting them.
    #[test]
    fn weights_that_are_not_the_format_are_refused() {
        let backend = StubBackend::new();
        let err = backend
            .load(&[0xff, 0xfe, 0xfd], &manifest(ModelKind::Chat))
            .expect_err("invalid weights are refused");
        assert_eq!(
            err,
            InferError::Weights("fixture weights are not UTF-8".to_string())
        );
    }

    /// A handle this backend never issued names nothing.
    #[test]
    fn an_unknown_handle_generates_nothing() {
        let backend = StubBackend::new();
        let model = Model {
            handle: ModelHandle(99),
            manifest: manifest(ModelKind::Chat),
        };
        let err = backend
            .generate(&model, &context("when?"), &Options::default())
            .expect_err("unknown handle is refused");
        assert_eq!(err, InferError::UnknownModel(99));
    }

    #[test]
    fn a_chat_model_may_not_be_asked_to_embed() {
        let backend = StubBackend::new();
        let model = backend
            .load(FIXTURE.as_bytes(), &manifest(ModelKind::Chat))
            .expect("fixture weights load");
        assert!(backend.embed(&model, "anything").is_err());
    }
}
