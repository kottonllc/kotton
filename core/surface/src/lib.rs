// SPDX-License-Identifier: AGPL-3.0-or-later
//! The `surface` domain — windows, and whose they are.
//!
//! Defines the abstraction for tracking open app-window instances, the
//! authoritative in-memory implementation, and the three verbs RFC-0054 assigns
//! this domain: `WindowOpened`, `WindowClosed`, `WindowList`.
//!
//! ## Why this is a domain and not part of `sys`
//!
//! It lived in `core/sys` until 2026-08-15, on the reasoning that a window
//! registry is a platform capability. It is not, and [`WindowOwner`] is the proof:
//! a window belongs to a principal, the daemon fills that principal in from the
//! authenticated session, and `window_list` filters by it. `sys` is defined by
//! RFC-0062 as
//! having *no opinion about who is asking*, which this module has been contradicting
//! since `WindowOwner` was added. Asked the RFC's own question — on whose authority
//! does a window act? — the answer names a domain, and RFC-0054 had already
//! ratified its name.
//!
//! See `docs/SHELL-MODEL.md` for design rationale and
//! `IDEA-surface-has-no-user` for the owner dimension.

pub mod commands;
pub mod registry;

pub use commands::{window_closed, window_list, window_opened};
pub use registry::InMemoryWindowRegistry;

use std::sync::Arc;
use tokio::sync::broadcast;
use uuid::Uuid;

/// Who a window belongs to.
///
/// Not a `user_id`, because the system draws windows too — a login prompt, a
/// lock screen, a user picker — and those exist before any session does, or
/// deliberately outside one. A registry that required a user could not represent
/// them.
///
/// The distinction is a trust boundary rather than bookkeeping. A user's app
/// must not be able to draw something the shell would render as a system
/// surface: Kotton's lock screen takes a PIN and its recovery flow takes a
/// recovery key, and with no identity authority to appeal to, a harvested
/// recovery key *is* the account. Every incumbent separates these structurally —
/// Windows renders UAC on a Secure Desktop user applications cannot read or draw
/// on, macOS runs `loginwindow` outside any user session, and Wayland
/// compositors run the greeter as a separate user while forbidding clients from
/// enumerating each other's surfaces at all.
///
/// Enforcement is by *absence*: no IPC verb lets a caller name its own owner —
/// the daemon fills it in from the authenticated session — so a guest cannot
/// claim [`WindowOwner::System`]. See `IDEA-surface-has-no-user`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum WindowOwner {
    /// Login, lock, user picker, device enrollment. Registered only by the shell.
    System,
    /// An app window belonging to a signed-in user, keyed by their DID.
    User(String),
}

impl WindowOwner {
    /// Whether a viewer with this owner may see `other`'s windows.
    ///
    /// A user sees their own and nothing else; the system sees its own. There is
    /// deliberately no "sees everything" case: a shell rendering a dock for one
    /// user asks as that user, and a shell needing two users' windows asks
    /// twice. A superuser view here would put back the whole problem the type
    /// exists to solve.
    pub fn may_see(&self, other: &WindowOwner) -> bool {
        self == other
    }
}

/// A snapshot of a single open app-window instance.
///
/// Kept deliberately small — only information the shell needs to render
/// dock badges, progress bars, and attention indicators.
#[derive(Debug, Clone, PartialEq)]
pub struct WindowState {
    /// Who this window belongs to. See [`WindowOwner`].
    pub owner: WindowOwner,
    /// Reverse-domain app identifier, e.g. `"sh.kotton.notes"`.
    pub app_id: String,
    /// Unique key for this particular open instance.
    pub instance_id: Uuid,
    /// Window title (may be the app name or a document name).
    pub title: String,
    /// Numeric badge count, if the app has requested one.
    pub badge: Option<u32>,
    /// Progress fraction in `[0.0, 1.0]`, if the app is reporting progress.
    pub progress: Option<f32>,
    /// Whether the app is requesting user attention (e.g. unsaved data).
    pub attention: bool,
}

/// Event emitted by [`WindowRegistry`] whenever any window state changes.
#[derive(Debug, Clone)]
pub enum WindowStateChanged {
    /// A new window was opened.
    Opened(WindowState),
    /// An existing window was closed.
    Closed { instance_id: Uuid },
    /// A window's metadata (title, badge, progress, attention) was updated.
    Updated(WindowState),
}

/// Trait abstracting the daemon's authoritative window-state store.
///
/// Today implemented as an in-memory table inside `DeviceRuntime`
/// (`crates/05_runtime/src/window_registry.rs`).  In a future Linux compositor
/// build, smithay would provide a compatible impl without changing either the
/// trait or the shell-window subscriber code.
pub trait WindowRegistry: Send + Sync + 'static {
    /// Register a newly opened app window under `owner`.
    ///
    /// Emits [`WindowStateChanged::Opened`] on the subscriber channel.
    fn window_opened(&self, owner: WindowOwner, app_id: String, instance_id: Uuid, title: String);

    /// Remove a closed app window.
    ///
    /// No-op if `instance_id` is not currently tracked **or** if `owner` does not
    /// own it. Closing is scoped even though an instance id is an unguessable
    /// UUID, because "you cannot guess it" is a property of the id rather than of
    /// the boundary, and the boundary is what this trait is for.
    ///
    /// Emits [`WindowStateChanged::Closed`] on the subscriber channel.
    fn window_closed(&self, owner: &WindowOwner, instance_id: Uuid);

    /// Snapshot the windows `viewer` may see, per [`WindowOwner::may_see`].
    ///
    /// There is no unfiltered variant. A caller wanting two owners' windows asks
    /// twice, which keeps every read site visibly scoped.
    fn window_list(&self, viewer: &WindowOwner) -> Vec<WindowState>;

    /// Subscribe to future state-change events.
    ///
    /// Any number of subscribers may hold a receiver.  Slow receivers that
    /// fall behind will receive a [`tokio::sync::broadcast::error::RecvError::Lagged`]
    /// error and should re-hydrate from [`window_list`].
    ///
    /// **This stream is unfiltered and has no consumers yet.** It carries every
    /// owner's events, so whoever wires the first subscriber owes it the filtering
    /// `window_list` does. A broadcast channel cannot filter per receiver, so that
    /// belongs where events leave the daemon rather than here. Wiring it without
    /// that reopens the hole [`WindowOwner`] exists to close.
    fn subscribe(&self) -> broadcast::Receiver<WindowStateChanged>;

    /// Convenience up-cast so callers can store a `Arc<dyn WindowRegistry>`.
    fn as_arc(self: Arc<Self>) -> Arc<dyn WindowRegistry>
    where
        Self: Sized,
    {
        self
    }
}
