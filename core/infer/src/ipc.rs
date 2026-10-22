// SPDX-License-Identifier: AGPL-3.0-or-later
//! IPC contract for the **inference channel** — `kuserd` ↔ `kinferd` (RFC-0085).
//!
//! **This lives in `core/infer`, not `core/wire` where every other channel's
//! frames live, and that is deliberate.** `kotton-wire` reaches `kotton-pair`,
//! so while these frames lived there the process that parses untrusted weights
//! linked a crypto stack it never calls — 137 crates including
//! `chacha20poly1305`, `curve25519-dalek`, `ed25519-dalek`, `x25519-dalek` and
//! `socket2`, measured 2026-09-16. None of it reached a key, so it was reach
//! rather than a leak; reach is what the second design test in `CLAUDE.md` asks
//! about, and the answer here was to move the frames rather than to write a rule
//! saying the parser must not use what it links.
//!
//! The cost is being the one channel whose wire lives outside `core/wire`.
//! RFC-0085 finding 3 named that trade and left it open; this is it taken.
//!
//! `kuserd` makes a pair of pipes at spawn and hands `kinferd` the far end as
//! its standard streams. There is no path, so there is nothing for a third
//! process to open and nothing for an acceptor to turn away: possession of the
//! descriptor is the authorisation, in both directions. That is the same
//! arrangement the compositor channel arrived at (`kotton_wire::kuid_ipc`), for the
//! same reason — a socket on the filesystem is reachable by every process of
//! that user, and RFC-0085 refuses a local model server *as the design* on
//! exactly that ground.
//!
//! ## Direction is the type
//!
//! | Type | Direction | Meaning |
//! |---|---|---|
//! | [`InferRequest`] | `kuserd` → `kinferd` | *Load this, or answer this.* |
//! | [`InferResponse`] | `kinferd` → `kuserd` | *A token, an answer, or a refusal.* |
//!
//! There is no wrapper here, where the compositor needed `kotton_wire::FromCompositor`:
//! `kinferd` raises nothing of its own. It answers, and it answers in order.
//!
//! ## One request, many frames — in both directions
//!
//! A generation streams, so one [`InferRequest::Generate`] is answered by a run
//! of [`InferResponse::Token`] frames and then exactly one terminator —
//! [`InferResponse::Done`] or [`InferResponse::Failed`]. That is why `kinferd`
//! cannot use `serve_inherited`, which is one request to one response, and reads
//! the channel itself.
//!
//! A load streams the other way, for a duller reason: a frame is capped at 32
//! MiB and a model is gigabytes. [`InferRequest::LoadBegin`] states what is
//! coming, [`InferRequest::LoadChunk`] carries at most [`MAX_LOAD_CHUNK`] bytes
//! of it, and [`InferRequest::LoadEnd`] is what makes the runtime parse. The
//! daemon reads those bytes out of the store under the unlocked context; what
//! crosses here is plaintext weights and nothing else. **No key material crosses
//! this channel in either direction**, which is the property `key-reach-check`
//! and `infer-check` hold from the two ends.
//!
//! ## What is deliberately absent
//!
//! - **A cancel verb.** Generation is cancellable at any token by dropping the
//!   stream (see [`crate::TokenStream`]); a verb would be a second way to
//!   stop, racing the first.
//! - **Anything naming a store, a path or a record.** A passage arrives with the
//!   *label* the host issued and the record url it stands for, as data the
//!   runtime may not resolve. IN6: a string the model produced never becomes a
//!   reference, and the runtime has nothing to resolve it against even if it
//!   tried.

use crate::{Context, InferError, Metering, ModelHandle, ModelManifest, Options};
use serde::{Deserialize, Serialize};

/// The most weight bytes one [`InferRequest::LoadChunk`] may carry.
///
/// Well under the 32 MiB frame ceiling `kotton_ipc` enforces, because a `Vec<u8>`
/// in JSON is an array of numbers at roughly four bytes to the byte — the same
/// arithmetic `kotton_wire::base64_bytes` exists for on the bulk-sealed path. A model
/// is loaded once per process, so the encoding cost is paid once and the
/// simplicity of one codec on the channel is worth more than the milliseconds.
pub const MAX_LOAD_CHUNK: usize = 1024 * 1024;

/// Sent by `kuserd` to the `kinferd` inference sidecar.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum InferRequest {
    /// Begin loading a model. Any partially received load is discarded.
    LoadBegin { manifest: Box<ModelManifest> },
    /// The next slice of the weights, in order, at most [`MAX_LOAD_CHUNK`] bytes.
    LoadChunk {
        #[serde(default)]
        bytes: Vec<u8>,
    },
    /// The weights are complete: parse them. Answered by
    /// [`InferResponse::Loaded`] or [`InferResponse::Failed`].
    LoadEnd,
    /// Answer a question from the passages the host selected and labelled.
    Generate {
        model: ModelHandle,
        context: Box<Context>,
        options: Options,
    },
    /// Embed one text with a `kind: embed` model.
    Embed { model: ModelHandle, text: String },
}

/// Sent by `kinferd` back to `kuserd`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum InferResponse {
    /// The weights parsed; this is the handle to generate against.
    Loaded { model: ModelHandle },
    /// One token, exactly as the runtime produced it — concatenating the run
    /// gives the answer back byte for byte.
    Token { text: String },
    /// The generation finished. Carries numbers and only numbers (IN9).
    Done { metering: Metering },
    /// The answer to an [`InferRequest::Embed`].
    Embedding { vector: Vec<f32> },
    /// The request failed, or a generation stopped partway. Anything already
    /// streamed has been streamed.
    Failed { error: InferError },
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The wire survives a round trip through the codec the channel uses. Kept
    /// beside the type, as `KuidRequest`'s is: each channel pins its own wire.
    #[test]
    fn the_inference_wire_round_trips() {
        let req = InferRequest::Generate {
            model: ModelHandle(7),
            context: Box::new(Context {
                question: "when was the boiler serviced?".to_string(),
                passages: vec![],
                template: "{question}".to_string(),
            }),
            options: Options::default(),
        };
        let json = serde_json::to_string(&req).expect("request encodes");
        let back: InferRequest = serde_json::from_str(&json).expect("request decodes");
        match back {
            InferRequest::Generate { model, context, .. } => {
                assert_eq!(model, ModelHandle(7));
                assert_eq!(context.question, "when was the boiler serviced?");
            }
            other => panic!("wrong variant: {other:?}"),
        }

        let resp = InferResponse::Done {
            metering: Metering {
                tokens: 12,
                first_token_ms: 40,
                total_ms: 300,
            },
        };
        let json = serde_json::to_string(&resp).expect("response encodes");
        let back: InferResponse = serde_json::from_str(&json).expect("response decodes");
        match back {
            InferResponse::Done { metering } => assert_eq!(metering.tokens, 12),
            other => panic!("wrong variant: {other:?}"),
        }
    }

    /// A refusal crosses as a typed error, so the daemon reports a stage rather
    /// than a sentence a runtime made up.
    #[test]
    fn a_refusal_crosses_as_a_typed_error() {
        let resp = InferResponse::Failed {
            error: InferError::UnknownModel(3),
        };
        let json = serde_json::to_string(&resp).expect("encodes");
        let back: InferResponse = serde_json::from_str(&json).expect("decodes");
        match back {
            InferResponse::Failed { error } => assert_eq!(error, InferError::UnknownModel(3)),
            other => panic!("wrong variant: {other:?}"),
        }
    }
}
