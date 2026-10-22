// SPDX-License-Identifier: AGPL-3.0-or-later
// Re-export the canonical IPC types from kotton_wire.
// The authoritative definitions live in crates/wire/src/ipc.rs.
// This file is kept so that `use protocol::{DeviceRequest, DeviceResponse}` in
// systemd/mod.rs continues to compile without changes.
pub use kotton_wire::ipc::{UserRequest, UserResponse};

// Suppress the dead-code warning on the old inline definitions (now removed).
// The original file content has been replaced — this comment is a tombstone.

/// TOMBSTONE — kept to satisfy `mod protocol;` in systemd/mod.rs
/// All types now live in kotton_wire::ipc.
///
/// Original stub below is intentionally absent; see wire/src/ipc.rs.
mod _removed {
    // Previously: pub enum DeviceRequest { ... }
    // Previously: pub enum DeviceResponse { ... }
}
