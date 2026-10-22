// SPDX-License-Identifier: AGPL-3.0-or-later
//! The three window verbs — `WindowOpened`, `WindowClosed`, `WindowList`.
//!
//! Free functions over a [`WindowRegistry`]. They took `&DeviceRuntime` until
//! 2026-08-15 and used exactly one of its nineteen fields, which is the shape
//! RFC-0062 says to
//! invert: a function takes what it uses, and nothing in these signatures can now
//! reach a key.
//!
//! Every function takes the `owner` acting, and none of them derives it. The daemon
//! supplies it from the authenticated session, which is the only place that knows
//! it — a verb that guessed would be asserting an authority it cannot check.

use uuid::Uuid;

use crate::{WindowOwner, WindowRegistry, WindowState};

/// Record that a WASM app window was opened, under `owner`.
///
/// Returns the windows `owner` may see after the insertion, so callers can confirm
/// the new state in a single round-trip if needed.
pub fn window_opened(
    registry: &dyn WindowRegistry,
    owner: WindowOwner,
    app_id: String,
    instance_id: Uuid,
    title: String,
) -> Vec<WindowState> {
    registry.window_opened(owner.clone(), app_id, instance_id, title);
    registry.window_list(&owner)
}

/// Record that a WASM app window was closed. A no-op unless `owner` owns it.
pub fn window_closed(registry: &dyn WindowRegistry, owner: &WindowOwner, instance_id: Uuid) {
    registry.window_closed(owner, instance_id);
}

/// Snapshot the windows `viewer` may see.
pub fn window_list(registry: &dyn WindowRegistry, viewer: &WindowOwner) -> Vec<WindowState> {
    registry.window_list(viewer)
}
