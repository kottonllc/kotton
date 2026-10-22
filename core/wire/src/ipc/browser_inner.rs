// SPDX-License-Identifier: AGPL-3.0-or-later
//! What travels *inside* a browser channel's seal (`DEC-0059`).
//!
//! The sealed framing outside this is `kotton_pair`'s: an ordered stream of
//! AEAD frames whose counter is **implicit**, derived on each side from how many
//! frames it has sent and received. Nothing on the wire says which frame this
//! is, so frames must be opened in order and a frame opened out of order does
//! not decrypt.
//!
//! That makes each direction an ordered channel — which is the substrate you
//! multiplex over — and it means the addressing has to live *inside* the seal.
//! Until 2026-09-07 the plaintext was a bare [`UserRequest`] one way and a bare
//! [`UserResponse`] the other, and the browser matched them by arrival order:
//! one frame in flight at a time, the next frame answers the oldest waiter. A
//! node with something to say that no request asked for had nowhere to put it,
//! which is why a pairing ceremony — three frames or more, arriving over the
//! time a person reads six digits aloud — could not reach a browser at all.
//!
//! So a call carries an `id` and every frame answering it carries the same
//! `id`. A single-response verb is one frame with `end`; a stream is frames
//! without it and then one with. The browser matches on the id, so a frame it
//! was not waiting for is a frame it can still place.

use serde::{Deserialize, Serialize};

use super::{UserRequest, UserResponse};

/// One call from the browser, inside the seal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelCall {
    /// The browser's own number for this call. Unique among the calls it has in
    /// flight; the node reads it and hands it back, and attaches no meaning of
    /// its own to the value.
    pub id: u64,
    pub request: UserRequest,
}

/// One frame from the node, inside the seal.
///
/// `response` is `None` only on the frame that closes a stream carrying nothing
/// further — every other frame has one. `end` is what says whether to keep the
/// call open, so a caller need not know in advance which verbs stream.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelFrame {
    /// The `id` of the [`ChannelCall`] this answers.
    pub id: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response: Option<UserResponse>,
    pub end: bool,
}

impl ChannelFrame {
    /// The whole of a single-response verb's answer.
    pub fn once(id: u64, response: UserResponse) -> Self {
        Self {
            id,
            response: Some(response),
            end: true,
        }
    }

    /// One frame of a stream, with more to come.
    pub fn more(id: u64, response: UserResponse) -> Self {
        Self {
            id,
            response: Some(response),
            end: false,
        }
    }

    /// The frame that closes a stream.
    pub fn done(id: u64) -> Self {
        Self {
            id,
            response: None,
            end: true,
        }
    }
}
