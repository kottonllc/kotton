// SPDX-License-Identifier: AGPL-3.0-or-later
//! A model as content (RFC-0085 IN1, IN3).
//!
//! *"A model is a hash-named, signed artifact with a manifest — its licence, its
//! size, its prompt shape, what it can do — installed by the person and kept as
//! a sealed object in their store."* This type is that manifest, and nothing
//! more: it **carries no authority**. A backend that has been handed a manifest
//! has been told what to expect of some bytes, not been given permission to do
//! anything.
//!
//! ## What is not here, and where it goes instead
//!
//! - **Verifying the publisher's signature.** That is a decision about whether
//!   to install, made above this crate by `kotton model add` against the
//!   person's own trust, and it happens once — at install — rather than every
//!   time a keyless sidecar is handed some bytes. [`ModelManifest::publisher`]
//!   is carried so the sidecar can report what it was told, never so it can
//!   decide.
//! - **Where the weights live.** RFC-0085's Mechanism sketch writes
//!   `load(&self, weights: SealedObjectRef, ..)`, and its prose rules the other
//!   way three sentences later: *"The daemon reads the weights out of the store
//!   under the unlocked context and streams the bytes to `kinferd` over the
//!   pipe, so the backend never touches a path the person did not open."* The
//!   prose wins and [`crate::Backend::load`] takes bytes. A `SealedObjectRef`
//!   here would be a name only the store can resolve, in a crate that must not
//!   link the store — the sketch's type cannot exist at this tier.

use serde::{Deserialize, Serialize};

/// The weights file format a backend must be able to parse.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ModelFormat {
    Gguf,
    Safetensors,
}

/// What a model is for. One manifest shape, three kinds (RFC-0085's index
/// section: *"the embedding model is a model like any other"*).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ModelKind {
    Chat,
    Embed,
    /// Named because the manifest shape must already admit it (RFC-0085 defers
    /// the model itself to the photo surface's first finding). No backend
    /// accepts one today.
    Vision,
}

/// The licence the weights carry, as an identifier and a hash of the text.
///
/// Article XI's line for content rather than code: *"A model's weights are
/// content, with a stated licence, a hash and a size, installed by the person."*
/// The hash is here so the text the person agreed to is the text that shipped.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Licence {
    /// SPDX identifier, e.g. `Apache-2.0`.
    pub spdx: String,
    /// Hex digest of the licence text as distributed.
    pub text_hash: String,
}

/// Everything the person and the runtime need to know about a model.
///
/// The identity of a model is [`ModelManifest::weights`] — the hash of the
/// sealed object — not its name. Two manifests naming the same hash describe
/// the same model however they spell it, which is what makes "did the model
/// change?" answerable (Article XII).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelManifest {
    /// For the person. Carries no authority: a model called `system` is a model
    /// called `system`.
    pub name: String,
    pub version: String,
    /// Hex hash of the sealed object holding the weights — the model's identity.
    pub weights: String,
    pub format: ModelFormat,
    pub kind: ModelKind,
    /// Parameter count, as the publisher states it.
    pub parameters: u64,
    /// e.g. `Q4_K_M`. A string because the vocabulary belongs to the format.
    pub quantisation: String,
    /// Bytes on disk. Shown before installing, because the store is paid by the
    /// byte.
    pub size: u64,
    /// How many tokens this model can be shown at once — the budget a host
    /// trims its passages to before asking.
    ///
    /// Here because the guest world already asks for it
    /// (`model-info.context-window` in `core/wasm/wit/kotton-app.wit`) and the
    /// manifest is the only truthful source: until a model was a record, the
    /// one value in the tree was a fixture's literal `4096`. `u32` is the WIT's
    /// width, so the two cannot disagree.
    pub context_window: u32,
    /// The prompt shape the model expects; copied into a [`crate::Context`] by
    /// the host that composes one.
    pub template: String,
    pub licence: Licence,
    /// Detached signature over the manifest, where the publisher signed one.
    ///
    /// Carried, never checked here — see this module's header.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub publisher: Option<String>,
}
