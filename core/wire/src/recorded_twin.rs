// SPDX-License-Identifier: AGPL-3.0-or-later
//! The one twin comparison of the recorded wire surfaces, beside their one reader
//! ([`crate::recorded_surface`]).
//!
//! A peer wire's recording (`peer-request-surface.txt`, `vault-peer-request-surface.txt`)
//! holds each of its verbs to the door's (`wire-surface.txt`), line for line. Each peer
//! wire's test calls [`each_verb_records_its_door_twin`], so the comparison is spelled once
//! and its failure message names the same files and lines wherever it is raised (kotton
//! #304; before it, `peer_request.rs` and `vault_peer_request.rs` each held a
//! word-for-word copy).
//!
//! This file is compiled for kotton-wire's tests only (`#[cfg(test)] mod recorded_twin` in
//! `lib.rs`). It is a sibling of `recorded_surface.rs` rather than part of it because that
//! file is also compiled into xtask by `#[path]` and must name nothing but `std`; this one
//! reads it through `crate::`. xtask's `wire-check` has its own twin rule (`line_diff`
//! findings, not a panic), and whether it should share this comparison is open.

use crate::recorded_surface::read;

/// The door's recording, `wire-surface.txt`, which every peer wire's recording is held to.
pub const DOOR_SURFACE: &str = include_str!("../wire-surface.txt");

/// A device's peer wire's recording, `peer-request-surface.txt`.
pub const PEER_SURFACE: &str = include_str!("../peer-request-surface.txt");

/// Variant names of a recorded surface, read by the one reader of the format, which holds
/// the recording to its own `# variants: N` header. It needs only the reader and the text,
/// so it sits here with the recordings it is asked of; `recorded_surface.rs` is compiled
/// into xtask, which has no use for it.
pub fn variants(surface: &str) -> Vec<&str> {
    read(surface)
        .unwrap_or_else(|e| panic!("a recorded surface cannot be read as one: {e}"))
        .into_iter()
        .map(|b| b.name)
        .collect()
}

/// Each verb of `twin` (recorded in `twin_file`) records its block in the door's
/// recording ([`DOOR_SURFACE`], `wire-surface.txt`), line for line.
pub fn each_verb_records_its_door_twin(twin_file: &str, twin: &str) {
    let door = read(DOOR_SURFACE).unwrap_or_else(|e| panic!("wire-surface.txt: {e}"));
    for block in read(twin).unwrap_or_else(|e| panic!("{twin_file}: {e}")) {
        let Some(door_block) = door.iter().find(|d| d.name == block.name) else {
            panic!("{} ({twin_file}:{}) is not on the door's surface", block.name, block.at);
        };
        assert_eq!(
            block.texts(),
            door_block.texts(),
            "{}'s fields: {twin_file}:{} against wire-surface.txt:{}",
            block.name,
            block.at,
            door_block.at
        );
    }
}
