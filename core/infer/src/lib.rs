// SPDX-License-Identifier: AGPL-3.0-or-later
//! The inference mechanism (RFC-0085).
//!
//! Mechanism tier (RFC-0080): **nobody's authority**. Nothing here has an
//! opinion about who is asking, and nothing here can find out — a [`Context`]
//! arrives already composed, already labelled, already selected. Who was
//! allowed to read the records behind those passages was decided by the host,
//! above this crate, before any of it was written down.
//!
//! ## What this crate may link, and why the list is an allow-list
//!
//! RFC-0085 IN1 splits the weights parser out of the daemon because *"a weights
//! file is untrusted input parsed by a large runtime, and the process that
//! parses it must not be the process that can open the store."* The crate that
//! defines the parser's interface is held to the sharper form of the same rule:
//! it links nothing that can open anything. `cargo xtask infer-check` holds it,
//! and it reads an **allow-list** — a deny-list of known networking crates
//! passes every socket-opening crate nobody thought of, which is the failure
//! mode a check is supposed to remove rather than reproduce.
//!
//! The allow-list is not the whole rule, because `std::net` needs no dependency
//! at all. The same check greps this crate's sources for socket-shaped names
//! from the standard library, for exactly that reason.
//!
//! ## The three pieces
//!
//! - [`Backend`] — what a runtime must be able to do. One implementation ships
//!   in-tree today ([`StubBackend`]), which "generates" by echoing a fixture, so
//!   that the pipe, the supervision and the keyless boundary are testable before
//!   any real model exists.
//! - [`ModelManifest`] — a model as *content*: a hash, a licence, a size, a
//!   prompt shape. It carries no authority (IN1), and nothing here verifies its
//!   publisher signature: installing a model is `kotton model add`'s job, above
//!   this crate and against the store.
//! - [`Context`] — the question and the host-labelled passages shown with it.
//!   IN6: every passage carries the record it came from, and a citation the
//!   model emits is resolved by the host against *these* labels or dropped.
//!
//! ## What this crate does not have
//!
//! No async runtime, no channel, no logging. [`Backend::generate`] hands back a
//! [`TokenStream`] the caller drives; the process that owns the pipe
//! (`kinferd`) decides what to do between tokens. IN9 — *nothing about a
//! question leaves the device* — is cheapest to keep when the crate holding the
//! question cannot write anywhere.

mod backend;
mod context;
mod manifest;
mod stub;

pub mod ipc;

pub use backend::{Backend, InferError, Metering, Model, ModelHandle, TokenStream};
pub use context::{Context, Options, Origin, Passage, Provenance};
pub use manifest::{Licence, ModelFormat, ModelKind, ModelManifest};
pub use stub::{StubBackend, FIXTURE};
pub use ipc::{InferRequest, InferResponse, MAX_LOAD_CHUNK};
