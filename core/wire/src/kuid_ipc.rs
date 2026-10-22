// SPDX-License-Identifier: AGPL-3.0-or-later
//! IPC contract for the **`kuid` socket** — the compositor channel (RFC-0018).
//!
//! `KuidRequest` / `KuidResponse` are the wire types for the socket `kuid`
//! is handed at spawn as its standard streams. It is
//! a different socket from the per-user `kuserd-{did_short}` one, and this is a
//! different conversation: **`kuserd` drives the display server**, and nothing
//! else speaks here.
//!
//! ## Direction is the type
//!
//! The channel is two-way and carries **two types, one per direction**:
//!
//! | Type | Direction | Meaning |
//! |---|---|---|
//! | [`KuidRequest`] | `kuserd` → `kuid` | *Do this to a surface.* |
//! | [`CompositorEvent`] | `kuid` → `kuserd` | *This is what I observed.* |
//!
//! The up direction shares its wire with [`KuidRequest`]'s replies, so it is
//! framed as [`FromCompositor`] — see that type for why the wrapper is forced
//! by the descriptor topology rather than chosen.
//!
//! RFC-0082's rule is one acceptor per request type, not one direction per
//! channel — so a second type satisfies it, and direction stays something the
//! compiler carries rather than a runtime arm that rejects. There is no
//! `KuidRequest` a client could build to travel the wrong way, and no
//! `CompositorEvent` kuserd could send back down.
//!
//! `KuidRequest`'s four variants used to live in `UserRequest`, which made
//! `kuid` the second acceptor of a 151-variant type it used four of, and left
//! the direction rule to a dispatch arm returning *"surface requests are
//! kuserd→kuid internal protocol"*.
//!
//! `CompositorEvent`'s variants came home the same way and later. They lived in
//! `UserRequest` too — as `SurfaceInputEvent`, `SurfaceError` and
//! `SurfaceClosed` — and this module's doc used to name them as the exception
//! it had to explain: *"traffic in the other direction is not part of this
//! channel"*. A channel doc that has to disclaim half its own traffic is
//! describing a split that does not hold. Moving them here is what let the
//! whole named-socket connection go (below).
//!
//! ## Authentication — who may speak on this channel
//!
//! **Nobody else can.** `kuserd` creates a `socketpair` before forking and hands
//! kuid the far end as its standard streams. There is no path, so there is no
//! way for a third process to reach this channel and nothing for an acceptor to
//! turn away — possession of the descriptor *is* the authorisation, in both
//! directions.
//!
//! This used to read "none, deliberately — the boundary is the socket
//! permission", describing a socket at a path that any process of this user
//! could open. Writing that sentence down under RFC-0082 rule 6 is what made it
//! obvious it should not be true, and the guards it needed — a `0o700`
//! directory, then a parent-pid admission check — are both gone rather than
//! relocated. Counting the guards is what pointed at the cause.
//!
//! ### What the second direction was worth — 2026-08-27
//!
//! Until this channel carried both directions, `kuid` also held a client
//! connection to kuserd's **named** socket, authenticated by a bearer token
//! read from `KUID_BOOTSTRAP_TOKEN`, over which it sent six verbs. That
//! connection is gone, and so is the token. Three of the six moved here; the
//! other three were deleted rather than moved, which is the more interesting
//! half:
//!
//! - `AppGetRole` + `AppLaunch` — kuid used these to resolve which app fills
//!   the `shell` role and launch it, at boot and again from the tray's *Open*.
//!   That is app-lifecycle **policy running inside the display server**. kuserd
//!   is the one booting, it spawned kuid, and it owns the `app_roles` table, so
//!   it launches the shell itself. The tray's *Open* became
//!   [`CompositorEvent::ShellReopenRequested`] — an intent kuserd interprets,
//!   not a launch kuid performs.
//! - `Authenticate` — with no client verb left there was nothing to
//!   authenticate for.
//!
//! The reason this mattered beyond tidiness: a session token names a **user**,
//! so every one of those six verbs was unreachable on a machine where no user
//! exists yet — which is every machine on its first boot. The fix could have
//! been a principal that is not a user
//! (`TASK-a-new-machine-has-no-display-server` costed it at fifteen call sites),
//! or adding the surface verbs to the pre-auth set (a real regression —
//! `SurfaceInputEvent` delivers a keystroke into a running app). Removing the
//! reachability instead means the question is not answered, it stops being
//! asked: there is no session to mint for a user who does not exist.


use serde::{Deserialize, Serialize};

use crate::surface::{SurfaceHandle, SurfaceRole};

/// Requests sent by `kuserd` to the `kuid` display server.
///
/// One direction, one acceptor. Adding a variant here is adding to the
/// compositor protocol; anything a *client* asks of kuserd belongs in
/// `UserRequest` instead.
///
/// ## Nothing here names an app — 2026-09-18
///
/// Every variant used to carry an `app_id`, and that was the whole of what a
/// surface *was*: the key was the app, so an app had exactly one surface and
/// could never have two (RFC-0087). They carry a [`SurfaceHandle`] now, minted
/// by the daemon once per launched instance.
///
/// The app id was not moved here as a second field beside the handle, which is
/// the shape this change exists to prevent: a field that is still there is a
/// field something will read, and what read it was `kuid` deciding which app
/// was the desktop by comparing against a constant. Which app holds a handle is
/// `kuserd`'s knowledge and stays on `kuserd`'s side of this wire
/// (`SurfaceProxy`); what `kuid` is told is what it has to draw — the title the
/// person approved at install, and the [`SurfaceRole`] the surface opens as.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KuidRequest {
    /// Create or show a surface.
    SurfaceOpen {
        handle: SurfaceHandle,
        /// What it opens as. `kuserd` reads the person's own designation to
        /// answer this; `kuid` holds no app roles and no default.
        ///
        /// One field, not a tier *and* a role: see [`SurfaceRole`]. `Window` is
        /// framed and stacked; `Background` and `Panel` are pinned, unframed,
        /// and reachable only through an interface an undesignated app does not
        /// have.
        role: SurfaceRole,
        /// The name the host draws in the frame: `manifest.app.name`, as the
        /// install prompt showed it. The guest cannot set it, cannot read it
        /// back, and is never asked.
        title: String,
        /// Which screen edge a `Panel` hangs from; `None` for every other role
        /// (RFC-0087 stage 3c).
        ///
        /// An `Option` rather than a member of [`SurfaceRole`] so that `Panel`
        /// stays one role — the RFC's own open question warns that guessing at
        /// panel sub-roles is how a role enum becomes a junk drawer — and so
        /// that the one role it means anything for is the only one that can
        /// carry it. A `Window` with an edge would be an app placing itself.
        edge: Option<crate::surface::PanelEdge>,
        width: u32,
        height: u32,
    },
    /// Commit a rendered patch to an existing surface.
    SurfaceCommit {
        handle: SurfaceHandle,
        /// Format: first byte is version (`0x00` = raw JSON transitional,
        /// `0x01` = full HTML string, `0x02` = reserved for Dioxus mutations).
        patch: Vec<u8>,
    },
    /// Close and destroy a surface.
    SurfaceClose {
        handle: SurfaceHandle,
    },
    /// Resize request forwarded from the guest's `surface.request-size` call.
    SurfaceResize {
        handle: SurfaceHandle,
        width: u32,
        height: u32,
    },
    /// What the holder of `handle` calls this window — the guest's
    /// `surface.set-title`, forwarded.
    ///
    /// **The one string on this wire the guest wrote**, and it is separate from
    /// the `title` on [`Self::SurfaceOpen`] for exactly that reason: that one is
    /// `manifest.app.name` as the install prompt showed it, and it is the
    /// attribution. This one is what the window is *about*, and the compositor
    /// draws it in the frame's bar in its own chrome — its font, its ink, its
    /// position, escaped as markup where it lands. Nothing about it is read back
    /// and nothing decides anything from it.
    ///
    /// Bounded before it gets here: `kuserd` cuts it to
    /// [`crate::surface::MAX_TITLE_CHARS`] at the call, so this wire never
    /// carries more, and a guest cannot make the compositor hold a string it
    /// chose the length of.
    SurfaceSetTitle {
        handle: SurfaceHandle,
        title: String,
    },
    /// The holder of `handle` asked for it to be brought to the front.
    ///
    /// **A request, not an instruction** (RFC-0087). The guest calls `raise` on
    /// the surface it holds; the daemon forwards that ask; `kuid` decides. A
    /// surface that is not in the app stack — the desktop — is not raisable by
    /// it, and no app can name another app's surface to raise, because it holds
    /// no resource for one.
    SurfaceRaise {
        handle: SurfaceHandle,
    },
    /// The **designated** app asked that a window be brought back to the person
    /// (RFC-0087 stage 3b): restored if they had minimised it, and raised.
    ///
    /// Separate from [`Self::SurfaceRaise`] because the two are different asks
    /// from different askers. `SurfaceRaise` is a guest asking about a surface
    /// it holds, and it deliberately does **not** un-minimise: a window the
    /// person put away does not come back because the app inside it would like
    /// it to. This one comes from the app the person designated, acting on a
    /// window it does not hold, and answering *where did my things go* — which
    /// is the only way back from minimise there is.
    ///
    /// The handle is one `kuserd` resolved from the asking instance's own list
    /// of ids; the designated app never sees a handle and cannot name one.
    SurfaceRestore {
        handle: SurfaceHandle,
    },
    /// **Draw the platform's own prompt**, on the compositor's prompt layer: above
    /// every window and the dock, below the menubar, over the whole desk blurred
    /// and darkened (`DEC-0081`).
    ///
    /// **Not a surface, and addressed by no [`SurfaceHandle`].** A surface is
    /// something a guest holds and draws into; this is a question only the
    /// platform asks, drawn by the compositor from the facts it names, in words
    /// and in a layer no guest reaches. No guest verb *is* this request: it is
    /// sent by the daemon's own door for a verb that needs the person's answer —
    /// today the landlord's drop, which asks for the pool's name typed back, and
    /// only once the door has checked that the person runs the vault and the vault
    /// keeps the pool, so a guest cannot put a question of its own invention on
    /// the desk (`dropped_once_typed_back`) — and the answer comes back up as
    /// [`CompositorEvent::PromptAnswered`] carrying the same `id`.
    ///
    /// One prompt at a time. A raise while another is up answers the older one
    /// as declined and shows the newer, so no question is ever left asked on a
    /// desk that no longer shows it.
    PromptRaise { id: u64, prompt: PlatformPrompt },
    /// Take prompt `id` down unanswered: the daemon stopped waiting for it.
    /// A withdraw for a prompt no longer up is nothing.
    PromptWithdraw { id: u64 },
}

/// **What the platform is asking**, as facts the compositor words and draws.
///
/// The facts and not the sentences: the compositor writes the question, in its
/// own document, escaped where each fact lands — so nothing that reaches a
/// prompt can bring markup or a look with it, including a name a guest chose.
/// The consent grant and the unlock take variants here when their units come
/// (`TASK-the-platforms-prompts-are-a-compositor-layer-over-a-dimmed-desk`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PlatformPrompt {
    /// Drop `pool` from the vault this person operates as `vault` — their
    /// sealed pool, identity chain and sealed recovery copy there, and their
    /// devices' pairings — confirmed by the pool's name typed back, as `vault
    /// drop <v> <name> --confirm <name>` and `kvaultd drop` ask for it.
    ///
    /// The compositor carries back what was typed; the daemon's door compares
    /// it. The compositor's own check — the button that acts only once the name
    /// is whole — is for the person, not the guard.
    DropTenant { vault: String, pool: String },
    /// Step `name` down as one of this machine's operators — every key of
    /// theirs — confirmed by their name typed back
    /// (`TASK-this-devices-operators-box-speaks-to-kdeviced-under-the-persons-own-key`).
    /// Their account and their data stay theirs; the machine keeps at least one
    /// operator, which the daemon checked before asking.
    RemoveOperator { name: String },
}

/// Replies from `kuid`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KuidResponse {
    /// The request was queued for the compositor's event loop.
    ///
    /// Delivery is best-effort by design: `kuserd` is the source of truth for
    /// app state, so a compositor that is absent or slow must not block it.
    SurfaceOk,
    /// The compositor could not act on the request.
    Error { message: String },
}

/// One window in [`CompositorEvent::WindowsChanged`] — the compositor's half of
/// a [`HostWindow`](crate::HostWindow).
///
/// Two fields, and neither is a name. The compositor has the title it draws in
/// the frame and deliberately does not send it back: a list assembled from what
/// `kuid` was told would be `kuserd` quoting its own words through a process
/// that has no need to be trusted with them. What travels up is what only this
/// side knows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompositorWindow {
    pub handle: SurfaceHandle,
    /// Alive, not painted, out of the stack — the state the frame's minimise
    /// control puts a window in, and the one thing in a window list that no
    /// other process can answer.
    pub minimised: bool,
}

/// Events sent by the `kuid` display server **up** to `kuserd`.
///
/// One direction, one acceptor — the mirror of [`KuidRequest`]. These are
/// *observations*, not requests: the compositor reports what happened at the
/// glass and kuserd decides what it means. That framing is why the tray's
/// *Open* is [`Self::ShellReopenRequested`] rather than a launch — deciding
/// which app fills the `shell` role, and whether to start it, is kuserd's call
/// on kuserd's data.
///
/// Possession of the handed descriptor is the authorisation (see the module
/// doc). There is no token and no session, which is what lets a compositor run
/// before any user exists.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CompositorEvent {
    /// A keyboard or pointer event on a surface, for kuserd to route to the
    /// WASM runner as `RunnerOp::Input`.
    ///
    /// The handle is the whole address. `kuid` could not name the owning app if
    /// it wanted to — it never learns one — which is the stronger form of the
    /// note the compositor's event drain already carried: *"an `app_id`
    /// arriving over a channel cannot vouch for whose app it is"*. Now nothing
    /// arrives that could.
    SurfaceInputEvent {
        handle: SurfaceHandle,
        event: crate::ipc::types::InputEventPayload,
    },
    /// A surface patch the compositor could not apply, after one retry. kuserd
    /// forwards `reason` to the holder's `on-surface-error` export.
    SurfaceError {
        handle: SurfaceHandle,
        reason: String,
    },
    /// The user dismissed a surface. kuserd tears down the instance that held
    /// it — otherwise it lingers and a relaunch is treated as "already running"
    /// and no-ops.
    SurfaceClosed {
        handle: SurfaceHandle,
    },
    /// The app stack changed: these are the `Window` surfaces there are, in
    /// paint order, front-most last (RFC-0087 stage 3b).
    ///
    /// Sent whenever a window opens, closes, is raised, minimised or restored —
    /// the compositor reporting what it has, not answering a question. There is
    /// no *list windows* request on this channel, because `kuserd` must not have
    /// to ask the display server for a fact a guest is waiting on: the ask would
    /// block a blocked host call behind a process that is free to be slow.
    ///
    /// **What is in it is what only the compositor knows** — membership, order,
    /// and which windows are minimised. It carries no title and no app id, so
    /// nothing about *whose* window this is round-trips through the display
    /// server: kuserd joins these handles against its own private record to say
    /// that, exactly as it does for every other event here.
    WindowsChanged { windows: Vec<CompositorWindow> },
    /// The user chose *Open* from the system tray.
    ///
    /// Deliberately not "launch the shell": kuid reports the gesture and kuserd
    /// resolves the role and starts it. Before this existed kuid did that work
    /// itself over the named socket, which is why it needed a session, which is
    /// why first run could not draw.
    ShellReopenRequested,
    /// The user chose *Quit Kotton* from the system tray: the daemon stops too.
    ///
    /// The one gesture that means *more than close this window*
    /// (`TASK-quit-kotton-stops-the-daemon-and-closing-the-window-does-not`).
    /// Closing the window is closing a window — kuid exits, `supervise_kuid`
    /// reads the clean status and stops supervising, and the daemon keeps
    /// replicating and delivering. This says the person is done with the
    /// daemon as well.
    ///
    /// **An observation, like every other variant here, and that is what keeps
    /// it inside the confinement thesis.** kuid does not stop the daemon: it
    /// says what happened at the glass, and kuserd decides that *the person
    /// quitting* means ending its own process. A `kill` from kuid to its parent
    /// would be reach the compositor does not have and must not gain — the
    /// record's *Not a signal* — and would still be reach on a machine where
    /// the compositor is the least trusted process in the picture.
    ///
    /// It carries nothing. There is no user in it, no reason and no status,
    /// because the only fact kuid holds is that a menu item was chosen; what
    /// that costs is kuserd's to decide.
    QuitRequested,
    /// **The person answered the platform's prompt `id`** — what they typed, or
    /// `None` when they declined it, the prompt was replaced by another, or the
    /// desk it was drawn on went away (`DEC-0081`).
    ///
    /// An observation like every other variant here: what was typed at the
    /// glass, not a verdict. Whether it is the name the verb needs is decided by
    /// the daemon's door that raised the prompt, which is the one place that
    /// knows what was asked. The reply to a guest's verb never carries it — the
    /// guest sees only that its verb succeeded or did not.
    PromptAnswered { id: u64, typed: Option<String> },
}

impl CompositorEvent {
    /// The variant's name, for logs and metrics.
    pub fn variant_name(&self) -> &'static str {
        match self {
            Self::SurfaceInputEvent { .. } => "SurfaceInputEvent",
            Self::SurfaceError { .. } => "SurfaceError",
            Self::SurfaceClosed { .. } => "SurfaceClosed",
            Self::WindowsChanged { .. } => "WindowsChanged",
            Self::ShellReopenRequested => "ShellReopenRequested",
            Self::QuitRequested => "QuitRequested",
            Self::PromptAnswered { .. } => "PromptAnswered",
        }
    }
}

/// Everything `kuid` writes on its end of the pair.
///
/// ## Why a wrapper exists at all
///
/// The child cannot rebuild a socket from a bare descriptor without `unsafe`,
/// which this workspace denies, so kuserd hands it one pair end as *both*
/// standard streams and kuid reads `stdin` and writes `stdout`. That fixes the
/// topology: **one readable fd in, one writable fd out**, and no room for a
/// third. A second `socketpair` would not help — it would land on the same two
/// std handles and split each direction the same way.
///
/// So the up direction carries two kinds of message on one wire, and the
/// discriminator has to be in the frame. That is this enum. kuserd's reader
/// routes a [`Self::Response`] to whichever [`KuidRequest`] is outstanding and
/// a [`Self::Event`] to the dispatcher.
///
/// The down direction needs no such wrapper, because events are **one-way**:
/// there is no ack. kuserd is the source of truth for app state and the
/// compositor must never block on it, so "the user pressed a key" is reported,
/// not asked. An earlier draft of this module had a `CompositorAck`; it carried
/// no information either end could act on, which is the tell.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FromCompositor {
    /// A reply to the [`KuidRequest`] kuserd is currently waiting on.
    Response(KuidResponse),
    /// Something the compositor observed, sent on its own initiative.
    Event(CompositorEvent),
}

impl KuidRequest {
    /// The variant's name, for logs and metrics.
    pub fn variant_name(&self) -> &'static str {
        match self {
            Self::SurfaceOpen { .. } => "SurfaceOpen",
            Self::SurfaceCommit { .. } => "SurfaceCommit",
            Self::SurfaceClose { .. } => "SurfaceClose",
            Self::SurfaceResize { .. } => "SurfaceResize",
            Self::SurfaceSetTitle { .. } => "SurfaceSetTitle",
            Self::SurfaceRaise { .. } => "SurfaceRaise",
            Self::SurfaceRestore { .. } => "SurfaceRestore",
            Self::PromptRaise { .. } => "PromptRaise",
            Self::PromptWithdraw { .. } => "PromptWithdraw",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every *surface* variant on this channel is addressed by handle. The two
    /// prompt variants are the compositor's own layer and address no surface —
    /// `a_prompt_is_no_surface_and_names_no_app` holds them.
    ///
    /// This replaces `the_move_did_not_change_the_wire`, which pinned the exact
    /// JSON these variants had inside `UserRequest` so that a `kuid` built
    /// before the split still parsed them. That compatibility claim is over:
    /// RFC-0087 changes the key, deliberately, and a test asserting the old
    /// bytes would now be asserting the defect. What is worth pinning instead
    /// is the property the change exists for.
    #[test]
    fn every_request_is_addressed_by_handle() {
        let h = crate::surface::SurfaceHandle::from_uuid(uuid::Uuid::nil());
        let requests = [
            KuidRequest::SurfaceOpen {
                handle: h,
                role: SurfaceRole::Window,
                title: "Editor".into(),
                edge: None,
                width: 1,
                height: 2,
            },
            KuidRequest::SurfaceCommit {
                handle: h,
                patch: vec![],
            },
            KuidRequest::SurfaceClose { handle: h },
            KuidRequest::SurfaceResize {
                handle: h,
                width: 1,
                height: 2,
            },
            KuidRequest::SurfaceRaise { handle: h },
            KuidRequest::SurfaceRestore { handle: h },
        ];
        for req in requests {
            let name = req.variant_name();
            let json = serde_json::to_string(&req).unwrap();
            assert!(
                json.contains(r#""handle":"00000000-0000-0000-0000-000000000000""#),
                "{name} does not address a surface by handle: {json}"
            );
            assert!(
                !json.contains("app_id"),
                "{name} still names an app on the compositor wire: {json}"
            );
        }
    }

    /// The role is what replaced `app_id == \"sh.kotton.shell\"`, and it says
    /// nothing about *which* app holds the surface.
    ///
    /// Both halves matter. Without a role, `kuid` cannot tell the screen's base
    /// from a window and the first screen does not draw; with an app id in it,
    /// the designation is back in the display server, which is what RFC-0087 is
    /// removing.
    #[test]
    fn the_role_is_a_position_not_an_identity() {
        for role in [
            SurfaceRole::Window,
            SurfaceRole::Background,
            SurfaceRole::Panel,
        ] {
            let json = serde_json::to_string(&role).unwrap();
            assert!(
                !json.contains('.'),
                "a role that spells an app id is the designation back in the \
                 display server: {json}"
            );
        }
        assert_eq!(
            serde_json::to_string(&SurfaceRole::Background).unwrap(),
            r#""Background""#
        );
    }

    /// The direction rule is the type, not a rejection arm: neither direction's
    /// wire form deserializes into the other's enum, so a message travelling the
    /// wrong way cannot be *built*, let alone accepted.
    ///
    /// This used to assert one half. The other half only became assertable when
    /// `CompositorEvent` existed — before that the kuid → kuserd direction had
    /// no type of its own, which is exactly the gap that let it ride the named
    /// socket instead.
    #[test]
    fn neither_direction_is_expressible_as_the_other() {
        let up = r#"{"SurfaceInputEvent":{"handle":"00000000-0000-0000-0000-000000000000","event":{}}}"#;
        assert!(serde_json::from_str::<KuidRequest>(up).is_err());

        let down = r#"{"SurfaceCommit":{"handle":"00000000-0000-0000-0000-000000000000","patch":[]}}"#;
        assert!(serde_json::from_str::<CompositorEvent>(down).is_err());
    }

    /// The up direction names no app either.
    ///
    /// The mirror of `every_request_is_addressed_by_handle`, and the half that
    /// matters most: what `kuid` *says* is what `kuserd` routes on. While these
    /// carried an `app_id`, the display server was naming whose app a keystroke
    /// belonged to — an assertion only `kuserd` can make, and one it now makes
    /// from its own map rather than from the frame.
    #[test]
    fn no_observation_names_an_app() {
        let h = crate::surface::SurfaceHandle::from_uuid(uuid::Uuid::nil());
        let events = [
            CompositorEvent::SurfaceClosed { handle: h },
            CompositorEvent::SurfaceError {
                handle: h,
                reason: "r".into(),
            },
        ];
        for event in events {
            let name = event.variant_name();
            let json = serde_json::to_string(&event).unwrap();
            assert!(
                json.contains(r#""handle":"00000000-0000-0000-0000-000000000000""#),
                "{name} does not address a surface by handle: {json}"
            );
            assert!(
                !json.contains("app_id"),
                "{name} still names an app on the compositor wire: {json}"
            );
        }
    }

    /// The tray reports a gesture; it does not name an app.
    ///
    /// If `ShellReopenRequested` ever gains an `app_id`, the compositor is
    /// choosing what to launch again and the reason this channel exists has
    /// quietly reverted. The unit variant is the enforcement.
    /// A response and an event are distinguishable on the shared up wire.
    ///
    /// The whole point of [`FromCompositor`]: kuserd's reader has to tell a
    /// reply to its own outstanding request from something kuid said on its own
    /// initiative, and the frame is the only place that distinction can live.
    #[test]
    fn the_up_wire_distinguishes_a_reply_from_an_observation() {
        let reply = serde_json::to_string(&FromCompositor::Response(KuidResponse::SurfaceOk))
            .unwrap();
        let observed = serde_json::to_string(&FromCompositor::Event(
            CompositorEvent::SurfaceClosed {
                handle: crate::surface::SurfaceHandle::mint(),
            },
        ))
        .unwrap();
        assert_ne!(reply, observed);

        assert!(matches!(
            serde_json::from_str::<FromCompositor>(&reply).unwrap(),
            FromCompositor::Response(_)
        ));
        assert!(matches!(
            serde_json::from_str::<FromCompositor>(&observed).unwrap(),
            FromCompositor::Event(_)
        ));
    }

    #[test]
    fn the_tray_event_carries_no_app_id() {
        let json = serde_json::to_string(&CompositorEvent::ShellReopenRequested).unwrap();
        assert_eq!(json, r#""ShellReopenRequested""#);
    }

    /// **The tray's two items are two different gestures on the wire.**
    ///
    /// `TASK-quit-kotton-stops-the-daemon-and-closing-the-window-does-not`. *Open*
    /// and *Quit* both travel as unit variants carrying nothing, and they are
    /// distinguishable — which is the whole of what this channel has to provide
    /// for the daemon to give them different meanings. The round trip is
    /// asserted because a variant that serialises and reads back as something
    /// else would make *Quit* silently mean *Open*, and the shape of these two
    /// (both unit, adjacent in the enum) is exactly where that goes wrong.
    #[test]
    fn quitting_and_reopening_are_two_gestures_on_one_wire() {
        let quit = serde_json::to_string(&CompositorEvent::QuitRequested).unwrap();
        let open = serde_json::to_string(&CompositorEvent::ShellReopenRequested).unwrap();
        assert_eq!(quit, r#""QuitRequested""#);
        assert_ne!(quit, open);
        assert!(matches!(
            serde_json::from_str::<CompositorEvent>(&quit).unwrap(),
            CompositorEvent::QuitRequested
        ));
        assert_eq!(
            CompositorEvent::QuitRequested.variant_name(),
            "QuitRequested"
        );
        // It says *quit*, and nothing else. A reason, a user or a status here
        // would be the compositor asserting something only kuserd can know.
        assert!(!quit.contains("app_id") && !quit.contains("user"));
    }

    /// The quit gesture survives the wrapper the up wire puts it in.
    ///
    /// `FromCompositor` is what kuserd's reader actually decodes, and the one
    /// frame this unit depends on is the one that ends the daemon — so it is
    /// read back through the wrapper rather than bare.
    #[test]
    fn the_quit_gesture_arrives_as_an_observation() {
        let framed =
            serde_json::to_string(&FromCompositor::Event(CompositorEvent::QuitRequested)).unwrap();
        match serde_json::from_str::<FromCompositor>(&framed).unwrap() {
            FromCompositor::Event(CompositorEvent::QuitRequested) => {}
            other => panic!("the quit gesture did not arrive as itself: {other:?}"),
        }
    }

    /// **A prompt is no surface and names no app** (`DEC-0081`).
    ///
    /// The prompt layer is the compositor's, so its requests carry no
    /// [`SurfaceHandle`] — a handle is what a guest holds, and a prompt addressed
    /// by one would be a prompt some guest's surface could be. And the answer
    /// travels up as an observation keyed by the prompt's own id, carrying what
    /// was typed and nothing about whose verb raised it.
    #[test]
    fn a_prompt_is_no_surface_and_names_no_app() {
        let prompt = PlatformPrompt::DropTenant {
            vault: "kotton".into(),
            pool: "sam".into(),
        };
        for req in [
            KuidRequest::PromptRaise { id: 7, prompt: prompt.clone() },
            KuidRequest::PromptWithdraw { id: 7 },
        ] {
            let name = req.variant_name();
            let json = serde_json::to_string(&req).unwrap();
            assert!(!json.contains("handle"), "{name} addresses a surface: {json}");
            assert!(!json.contains("app_id"), "{name} names an app: {json}");
            let back: KuidRequest = serde_json::from_str(&json).unwrap();
            assert_eq!(back.variant_name(), name);
        }
        for typed in [Some("sam".to_owned()), None] {
            let framed = serde_json::to_string(&FromCompositor::Event(CompositorEvent::PromptAnswered {
                id: 7,
                typed: typed.clone(),
            }))
            .unwrap();
            assert!(!framed.contains("handle") && !framed.contains("app_id"), "{framed}");
            match serde_json::from_str::<FromCompositor>(&framed).unwrap() {
                FromCompositor::Event(CompositorEvent::PromptAnswered { id: 7, typed: back }) => {
                    assert_eq!(back, typed)
                }
                other => panic!("the answer did not arrive as itself: {other:?}"),
            }
        }
    }

    /// **No guest verb names the prompt layer or the dim** (`DEC-0081`,
    /// `TASK-the-platforms-prompts-are-a-compositor-layer-over-a-dimmed-desk`).
    ///
    /// The ruling's second clause: a dim across the whole desk is a signal only
    /// while nothing a guest can say produces it, so there is no verb for it on
    /// the guest's wire and never will be — the rule is an absence, and an
    /// absence is held by reading everything a guest can say. That is three
    /// files: the WIT a guest imports, the runner wire its imports become
    /// (`runner.rs` — every host call, verb and output), and the surface roles
    /// and edges a guest may ask to open (`surface.rs`, where a `Prompt` role or
    /// a `dim` field on a panel would be the breach in its most likely shape).
    /// This crate's two are read here. The WIT is the SDK's, and a release of
    /// this crate ships without it, so the SDK's own test reads it against these
    /// words (`no_import_names_the_prompt_layer_or_the_dim`, in
    /// `guest/sdk/kotton-app/src/host_wire_tests.rs`), taking them from this
    /// test so there is one list.
    ///
    /// Read as source, comments and string literals stripped, every identifier
    /// split at case and at `-`/`_`: a variant, a field, a type, a function or an
    /// interface whose words include the prompt layer's or the dim's is a verb
    /// that reaches them. The compositor's own wire — this file — is not read:
    /// only the daemon speaks it.
    #[test]
    fn no_guest_verb_names_the_prompt_layer_or_the_dim() {
        const RUNNER: &str = include_str!("runner.rs");
        const SURFACE: &str = include_str!("surface.rs");
        // What the layer and the dim are called anywhere they are named.
        const THE_LAYERS_WORDS: [&str; 11] = [
            "prompt", "prompts", "dim", "dims", "dimmed", "dimming", "scrim", "veil", "mist",
            "darken", "shade",
        ];
        for (file, src) in [("runner.rs", RUNNER), ("surface.rs", SURFACE)] {
            for word in guest_words(src) {
                assert!(
                    !THE_LAYERS_WORDS.contains(&word.as_str()),
                    "{file} gives a guest the word `{word}` — a verb, field or role that \
                     reaches the prompt layer or the dim, which only the compositor may draw"
                );
            }
        }
    }

    /// Every word of every identifier in `src`, lowercased, with `//` comments
    /// and string literals taken out first.
    fn guest_words(src: &str) -> Vec<String> {
        let mut code = String::new();
        for line in src.lines() {
            let line = match line.find("//") {
                Some(at) => &line[..at],
                None => line,
            };
            let mut in_str = false;
            let mut escaped = false;
            for c in line.chars() {
                if in_str {
                    match (escaped, c) {
                        (true, _) => escaped = false,
                        (false, '\\') => escaped = true,
                        (false, '"') => in_str = false,
                        _ => {}
                    }
                    continue;
                }
                if c == '"' {
                    in_str = true;
                    code.push(' ');
                } else {
                    code.push(c);
                }
            }
            code.push('\n');
        }
        // Rust's tests are the file's own business, not a guest's wire: each
        // `#[cfg(test)]` item is cut out to its closing brace — and only it. A
        // test module can sit in the middle of a file (`runner.rs` has one
        // above half its verbs), so cutting at the first one would leave
        // everything after it unread.
        while let Some(at) = code.find("#[cfg(test)]") {
            let Some(open) = code[at..].find('{').map(|o| at + o) else {
                code.truncate(at);
                break;
            };
            let mut depth = 0usize;
            let mut end = code.len();
            for (i, c) in code[open..].char_indices() {
                match c {
                    '{' => depth += 1,
                    '}' => {
                        depth -= 1;
                        if depth == 0 {
                            end = open + i + 1;
                            break;
                        }
                    }
                    _ => {}
                }
            }
            code.replace_range(at..end, "");
        }
        let mut words = Vec::new();
        for ident in code.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == '-')) {
            for part in ident.split(['_', '-']) {
                let mut word = String::new();
                for c in part.chars() {
                    if c.is_ascii_uppercase() && !word.is_empty() {
                        words.push(std::mem::take(&mut word));
                    }
                    word.push(c.to_ascii_lowercase());
                }
                if !word.is_empty() {
                    words.push(word);
                }
            }
        }
        words
    }
}
