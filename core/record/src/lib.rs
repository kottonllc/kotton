// SPDX-License-Identifier: AGPL-3.0-or-later
//! The `record` domain.
//!
//! Laid out by tier within the domain (RFC-0059); `provider` holds the
//! implementations. Higher tiers arrive as `05_runtime` and `06_daemon`
//! dissolve.

/// The `record` domain's **daemon tier** — the IPC verbs over a user's records.
///
/// Moved here from `kuserd` 2026-08-21. `handlers/records.rs` reached zero
/// references to the runtime crate on 2026-08-20, when the caller took over
/// resolving the record store and schema registry; what kept it in the daemon
/// after that was only that nobody had moved it.
pub mod immediate;
pub mod open;
pub mod daemon;
pub mod provider;
/// The authoritative in-process schema registry.
///
/// Moved here from `05_runtime` (RFC-0059/RFC-0060): a registry of record
/// schemas is record-domain state, and it sat on `DeviceRuntime` only because
/// that struct held everything. It depends on `kotton_schemas` and nothing else,
/// so the move costs no dependency.
pub mod registry;
pub mod ics;
pub mod import_cmds;
pub mod record_cmds;
pub mod replication;
/// Which roots a person may read and write records in (RFC-0071 R12, R17).
pub mod roots;
pub mod schema_cmds;

pub use provider::*;
pub use registry::{SchemaError, SchemaRegistry};
