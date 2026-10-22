// SPDX-License-Identifier: AGPL-3.0-or-later
//! What the host calls a surface, on every wire that mentions one (RFC-0087).
//!
//! A surface used to be named by the app that drew into it: every compositor
//! message carried an `app_id`, so an app had exactly one surface and could
//! never have two. [`SurfaceHandle`] replaces that name. The daemon mints one
//! per launched instance, hands one copy to `kuid` and one to the runner, and
//! keeps the association between a handle and the app that holds it to itself.
//!
//! ## Why the handle is random rather than a counter
//!
//! It crosses a confinement boundary. The daemon sends the handle to the
//! runner, which turns it into a `surface` resource the guest holds — so
//! whatever the value *says* is something a confined process can read. A
//! counter says how many surfaces this machine has opened, which is a fact
//! about the person rather than about the surface, and two apps holding two
//! counters can order themselves in time. A v4 UUID says nothing but *which
//! one*, which is the whole of what a handle is for.
//!
//! The unforgeability is not in the value. On the kuserd → kuid wire it comes
//! from the channel: that pair is handed over at spawn and has no path, so
//! possession of the descriptor is the authorisation
//! ([`crate::kuid_ipc`]). On the guest side it comes from the component model:
//! the guest holds a `resource`, never this value, so there is nothing for it
//! to guess at.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A surface, as the host names it.
///
/// Minted by the daemon at launch — see `spawn_and_present` in
/// `core/app/src/daemon/apps.rs`, which is the only place in the tree that
/// calls [`SurfaceHandle::mint`]. Everything else receives one.
///
/// Opaque on purpose: nothing outside this type reads its bytes, and no
/// `app_id` can be recovered from it. That is what stops a handle being a join
/// key — two observers holding the same handle learn that they are looking at
/// the same surface, which they already knew, and nothing else.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SurfaceHandle(Uuid);

impl SurfaceHandle {
    /// Mint a fresh handle. The daemon does this; nothing else should.
    pub fn mint() -> Self {
        Self(Uuid::new_v4())
    }

    /// A handle built from a known value, for tests and for the one place a
    /// handle arrives as text.
    ///
    /// Not a way to *forge* one: on the guest side there is no value to build
    /// from, and on the kuid wire a handle nobody opened names no surface, so
    /// every lookup misses.
    pub fn from_uuid(id: Uuid) -> Self {
        Self(id)
    }
}

impl std::fmt::Display for SurfaceHandle {
    /// Short form, for logs. Long enough to tell two surfaces apart in a trace
    /// and short enough to read; the full value is in the serialised frame if
    /// anyone ever needs it.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = self.0.simple().to_string();
        write!(f, "{}", &s[..8])
    }
}

/// What a surface **is**, as the host draws it (RFC-0087, *Guide-level
/// explanation*).
///
/// Stage 1 carried `SurfaceTier { System, App }` here — the top-level division,
/// moved off the `app_id` it used to be drawn on. Stage 2 replaces it with the
/// role rather than adding the role beside it, because two fields for one fact
/// is two fields that can disagree, and `kuid` would have had to pick a winner.
/// The tier is still derivable ([`Self::is_system`]) and is no longer something
/// anybody can state independently of the role.
///
/// The three members are the RFC's own, and there is no fourth for "the
/// desktop": the surface that *is* the output's base is a [`Self::Background`],
/// which is what `kuid` has drawn since composited layers existed — the shell's
/// document painted first, below every layer. One model, degrading to one
/// output.
///
/// Where the value comes from is unchanged and is the part worth keeping:
/// `kuserd` owns `app_roles`, so `kuserd` says what a surface opens as, and
/// `kuid` draws what it is told. Until 2026-09-18 `kuid` compared the incoming
/// `app_id` against a hardcoded `sh.kotton.shell` — the designation living in
/// the display server, *"losing to a constant in the process that was least
/// entitled to hold it"*.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SurfaceRole {
    /// An ordinary window. Framed by the host, in the one app stack, raisable.
    ///
    /// The only role reachable from `world app`: the guest-facing enum in that
    /// world has this member and no other, so an undesignated app cannot name
    /// the two below, let alone be refused them.
    Window,
    /// The screen's base: below the app stack, unframed, not raisable.
    ///
    /// Held by whichever app the person designated, through the `layer-surface`
    /// interface only the designated world carries.
    Background,
    /// A menubar, a dock, a status strip: above the app stack, unframed, not
    /// raisable. Same holder, same interface.
    ///
    /// A panel also names the screen edge it hangs from ([`PanelEdge`]) —
    /// carried beside the role on the open, not inside it, so `Panel` stays one
    /// role rather than becoming one per edge.
    Panel,
}

/// Which screen edge a [`SurfaceRole::Panel`] hangs from (RFC-0087 stage 3c).
///
/// **An anchor, not a position.** The invariants forbid an app placing itself,
/// and this does not breach that: the app says *which edge I belong to* and the
/// host decides everything else — the span, the offset, and what is left over
/// for windows. It is `wlr-layer-shell`'s `anchor` with two of its four members,
/// which is the prior art RFC-0087 already cites, and it is the least an edge
/// can be expressed in.
///
/// Why it has to be expressed at all: a menubar and a dock are both full-width
/// strips a few tens of pixels tall, so nothing about the surface distinguishes
/// them. A host that guessed would put the dock at the top on the first launch
/// and be right half the time. Left and right are absent because nothing in the
/// tree wants one yet and a member added ahead of its first user is a member
/// nobody has had to make work.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PanelEdge {
    /// The top of the output. A menubar.
    Top,
    /// The bottom of the output. A dock.
    Bottom,
}

/// What a surface opens as: everything about it that is fixed when it is minted.
///
/// **One named argument, because the alternative was eight positional ones.** Adding
/// `edge` at RFC-0087 stage 3c took `AppHost::surface_open` and `SurfaceProxy::open` to
/// eight, which is `clippy::too_many_arguments` — and the warning is right, not noise: a
/// call reading `(handle, app_id, role, None, title, 1200, 800)` has two integers and a
/// bare `None` in it whose meaning is only recoverable from the signature, which is how
/// a width and a height get passed the wrong way round. `SurfaceRole::Window` and a
/// `PanelEdge` are the two the compiler already catches; `width` and `height` are not.
///
/// It does **not** carry the handle or the app id. Those are the two facts about *who*,
/// and RFC-0087 keeps them apart from the facts about *what*: the handle is minted by the
/// daemon and the app id never crosses the compositor wire at all, while every field here
/// is something `kuid` is told.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SurfaceSpec {
    /// What it opens as. `Window` is framed and stacked; `Background` and `Panel` are
    /// pinned, unframed, and reachable only through an interface an undesignated app
    /// does not have.
    pub role: SurfaceRole,
    /// Which screen edge a `Panel` hangs from; `None` for every other role.
    pub edge: Option<PanelEdge>,
    /// The name the host draws in the frame: `manifest.app.name`, as the install prompt
    /// showed it. The guest cannot set it, cannot read it back, and is never asked.
    pub title: String,
    /// The size the surface asks for. A request, not a grant — the compositor fits it to
    /// the work area and may hand back less.
    pub width: u32,
    pub height: u32,
}

impl SurfaceRole {
    /// Whether this is a system-tier surface — the half of the RFC's division
    /// an undesignated app cannot reach.
    ///
    /// A function rather than a second field, so nothing can hold a role and a
    /// tier that disagree.
    pub fn is_system(self) -> bool {
        matches!(self, Self::Background | Self::Panel)
    }
}

/// How many surfaces one instance may hold at once (RFC-0087, *Invariants*).
///
/// **The number is an implementation choice; its absence is not.** Without a cap
/// `create-surface` is unbounded reach: a guest in a loop can make the host mint
/// handles and open documents until the machine stops, which is a denial of
/// service written by an app the person installed.
///
/// Named here rather than at the one place that compares against it, because the
/// RFC asks for *a cap named in one place* and a constant written at its
/// enforcement site is a constant that acquires a second copy the first time a
/// second site needs it. It counts the launch surface, so an app may ask for one
/// fewer than this many more.
///
/// **Thirty-two since 2026-09-19 (stage 3c), and eight before it.** Eight was
/// chosen while nothing in the tree held more than one, as *"more windows than
/// any app in this tree opens"*. Stage 3c made that false in the one app it had
/// to: the designated shell holds a `Background`, a `Panel` per screen edge and
/// **one `Window` per window the person has open**, so eight capped a desktop at
/// five windows — and the failure is the sixth window silently not opening,
/// which reads as the desktop being broken rather than as a limit being met.
/// Thirty-two is past what a person opens and still a bounded cost: RFC-0087's
/// measurement puts a document at ~12 ms to construct and ~11 ms/frame to paint
/// at N=8 on the CPU renderer, and a person with thirty-two windows open has a
/// slow desktop for reasons the cap cannot fix.
///
/// It is still the *cap* rather than a budget: the reason it exists is that
/// `create-surface` is unbounded reach without one — a guest in a loop can make
/// the host mint handles and open documents until the machine stops, which is a
/// denial of service written by an app the person installed.
pub const MAX_SURFACES_PER_INSTANCE: usize = 32;

/// The longest title a guest may give one of its surfaces, in **characters**.
///
/// A bound rather than a limit the compositor discovers: `surface.set-title` is
/// the one place in this world where a guest hands the host a string the host
/// will *hold* — kept per surface, redrawn on every focus change, and carried in
/// every window list — so an unbounded one is a guest choosing how much of the
/// host's memory a window costs, and how wide the host's own bar has to be able
/// to render.
///
/// **Characters, not bytes**, so the bound means the same thing in every script;
/// the cut is made on a `char` boundary, so a truncated title is still a string.
/// **Truncated rather than refused**, which is the pen principle this repository
/// states (`CLAUDE.md`, and RFC-0072 X2): the confined thing names what it wants
/// and the host writes what actually happens. A refusal would put the host's
/// bound into the guest's error path, where an app that did not read it would
/// end up with the manifest name and no idea why.
///
/// 128 because a title bar that is the full width of a 1280px desk holds roughly
/// that many characters at `--text-footnote`, so the bound is past what can be
/// read and far short of what can be hoarded.
pub const MAX_TITLE_CHARS: usize = 128;

/// One open `Window` surface, as the **host** holds it (RFC-0087 stage 3b).
///
/// The host's own view, keyed by the handle nothing outside this daemon ever
/// sees. It is assembled where both halves are known: `kuid` says which windows
/// are in the stack and which of them are minimised, and `kuserd` says what each
/// one is called, out of the private `handle -> app` record it wrote when it
/// opened the surface. Neither half is asked to vouch for the other's.
///
/// **Two strings, and the difference between them is the whole of what a window
/// list can be trusted for.** `name` is `manifest.app.name`, as the install
/// prompt showed it, and it is the host's: no guest writes it and no guest can.
/// `title` is what the app inside the window calls that window — the one value
/// here a guest supplied — and it is `None` until the holder says one.
///
/// A `title` therefore says what a window is *about* and never who it belongs
/// to. A reader that wants attribution reads `name`; a reader that wants to tell
/// one of an app's windows from another reads `title` beside it. It was absent
/// from this type until
/// `TASK-a-window-has-a-title-and-the-menubar-carries-the-apps-name`, on the
/// grounds that *nothing a guest supplied travels in this type* — which was the
/// right rule while there was only one string and it was the attribution. Two
/// named strings keep that property where it matters and let a dock say which
/// folder a Files window is showing.
///
/// What is still absent is as deliberate: no app id, no surface handle in the
/// guest's copy of this, no size, no position.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostWindow {
    /// Which surface this is, on the host's side of every wire.
    pub handle: SurfaceHandle,
    /// The name the host puts on this window: `manifest.app.name`, approved at
    /// install. Never anything the guest sent.
    pub name: String,
    /// What the app inside calls this window, bounded to
    /// [`MAX_TITLE_CHARS`], or `None` where it has not said.
    pub title: Option<String>,
    /// Alive, not painted, out of the stack.
    pub minimised: bool,
}

/// One open `Window` surface, as the **designated app** is told about it.
///
/// [`HostWindow`] with the handle replaced by an id minted for the asking
/// instance, which is the only difference and the reason this is a second type
/// rather than a field the caller is trusted to leave alone. A handle is minted
/// per *machine* and is what every surface wire is addressed by; handing one to
/// a guest would give it a name for a window it does not hold, and a value that
/// composes across apps and across time. The id counts the windows **this
/// instance has been shown**, is meaningless to anybody else, and dies with the
/// instance that was given it.
///
/// It buys no reach beyond the one ask it is an argument to: `raise-window`
/// resolves it against the asking instance's own list, so an id the instance was
/// never given names nothing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowView {
    /// This instance's name for the window, from 1. Never reused: an id that
    /// came back pointing at a different window is the stage-3a ordinal defect
    /// one level up.
    pub id: u64,
    /// The host's attribution — `manifest.app.name`, as approved at install.
    pub name: String,
    /// What the app inside calls this window, bounded to [`MAX_TITLE_CHARS`],
    /// or `None` where it has not said. See [`HostWindow`] for why the two are
    /// separate fields rather than one string that means either.
    pub title: Option<String>,
    /// Whether the person has put it out of the way.
    pub minimised: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two mints are two surfaces. This is the whole of "a second launch of the
    /// same app gets a different handle" — under `app_id` keying the two were
    /// the same string and therefore the same surface, which is why an app
    /// could only ever have one.
    #[test]
    fn every_mint_is_a_different_surface() {
        let a = SurfaceHandle::mint();
        let b = SurfaceHandle::mint();
        assert_ne!(a, b);
    }

    /// The handle is one scalar on the wire, not a record with fields somebody
    /// could add an app id to.
    #[test]
    fn a_handle_is_an_opaque_scalar_on_the_wire() {
        let h = SurfaceHandle::from_uuid(Uuid::nil());
        let json = serde_json::to_string(&h).unwrap();
        assert_eq!(json, r#""00000000-0000-0000-0000-000000000000""#);
        assert_eq!(serde_json::from_str::<SurfaceHandle>(&json).unwrap(), h);
    }

    /// The tier is a function of the role, so nothing can hold a pair that
    /// disagrees.
    ///
    /// This is the answer to RFC-0087 stage 2's fourth clause — *"`SurfaceTier`
    /// either becomes the role or sits beside it"*. It became the role. A second
    /// field would have been a second thing `kuid` is told, and two things told
    /// separately are two things that can arrive contradicting each other.
    #[test]
    fn the_tier_is_derived_from_the_role_and_not_stated_beside_it() {
        assert!(!SurfaceRole::Window.is_system());
        assert!(SurfaceRole::Background.is_system());
        assert!(SurfaceRole::Panel.is_system());
    }

    /// The cap exists and counts more than the one surface stage 1 allowed.
    ///
    /// A test on a constant, which is worth writing exactly once: what RFC-0087
    /// requires is *a cap*, and the failure it guards against is somebody
    /// removing it or setting it to a number that makes `create-surface` either
    /// useless or unbounded.
    #[test]
    fn an_instance_may_hold_several_surfaces_but_not_unboundedly_many() {
        // Read through a binding rather than asserted on the constant itself:
        // `assert!(CONST > 1)` is a constant expression, which clippy calls out
        // as an assertion that cannot fail — and it is right about the shape even
        // though the point here is to fail when somebody edits the constant.
        let cap = MAX_SURFACES_PER_INSTANCE;
        assert!(cap > 1, "a cap of one is stage 1 with extra steps");
        assert!(
            cap <= 64,
            "a cap this large is not a cap: `create-surface` is unbounded reach \
             without one (RFC-0087, Invariants)"
        );
    }

    /// Nothing about the app can be read back out of a handle.
    ///
    /// Stated as a test rather than a comment because the cheapest way to lose
    /// it is for someone to make the handle `format!("{app_id}-{n}")` while
    /// fixing a debugging session, and that would still pass every other test
    /// in the tree.
    #[test]
    fn a_handle_carries_nothing_of_the_app_that_holds_it() {
        let h = SurfaceHandle::mint();
        let text = serde_json::to_string(&h).unwrap();
        assert!(
            !text.contains("kotton") && !text.contains('.'),
            "a handle that spells an app id is a join key: {text}"
        );
    }
}
