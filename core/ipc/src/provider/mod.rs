// SPDX-License-Identifier: AGPL-3.0-or-later
//! IPC provider implementations

use std::io;

#[cfg(feature = "os-provider")]
pub mod client;
pub mod memory;
#[cfg(feature = "os-provider")]
pub mod os;
#[cfg(feature = "os-provider")]
pub mod acceptor;

#[cfg(feature = "os-provider")]
pub use client::IpcClient;
pub use memory::MemoryConnection;
pub mod inherited;
pub use inherited::{
    read_frame, serve_inherited, write_frame, FrameRead, Refusal, MAX_FRAME_LEN,
};
/// The far end of an inherited channel, for a test that has to be the peer.
/// Gated so only a dev-dependency can reach it — see the module's header for
/// why it is not simply [`read_frame`].
#[cfg(any(test, feature = "test-utils"))]
pub mod test_peer;
#[cfg(feature = "os-provider")]
pub use os::{AcceptedConnection, Caller, OsConnection, OsListener, OsUserId};
#[cfg(feature = "os-provider")]
pub use acceptor::{ChannelAcceptor, HandlerOutput};

/// What a handler's `Err` becomes, at both doors: the channel's own error frame
/// for the peer, and the error's **kind** — never its text — for the log.
///
/// **The rule, once.** [`serve_inherited`] and `ChannelAcceptor` both answer a
/// handler's error through here, and neither logs it any other way. They made
/// opposite calls about the log until 2026-09-28, a day apart
/// (`TASK-the-two-ipc-doors-log-a-handlers-error-differently`): the inherited
/// loop logged the kind, the acceptor logged `error = %e` at `debug`.
///
/// **Why the kind and not the text.** The text is written from the request, so
/// it can quote the request back, and on the inherited channels it does: their
/// peers carry prompts and passages (RFC-0085 IN9). (The `invalid connection
/// code: …` texts in `pairing.rs` are fixed strings and never carry what was
/// typed; the rule is set by the channels whose text does.) The frame takes that
/// text to the one person who asked, who already has it. A log line takes it to
/// whoever reads the daemon's host. The weakest host is `kvaultd`'s: a node a
/// person *rents*, whose log is the landlord's, where line after line composes
/// into a record of what tenants asked, kept by someone who is not them — the
/// question CLAUDE.md's first design test asks. The rule is set at that door
/// and applied to every door, kuserd's on the person's own machine included,
/// because one rule reached is the shape that holds. So the text goes to the
/// peer and nowhere else.
///
/// **What the host's log loses**, said rather than implied: which handler
/// refused and in what words. What it keeps is that a handler on this door
/// failed, and how (`NotFound`, `PermissionDenied`, `Other`). The words are
/// still said, to the person who can report them — which is where a question
/// about their own request belongs.
pub(crate) fn answer_for_a_handlers_error<Resp: From<io::Error>>(
    door: &'static str,
    e: io::Error,
) -> Resp {
    tracing::debug!(door, kind = ?e.kind(), "handler failed; answering the peer");
    Resp::from(e)
}

#[cfg(all(test, unix))]
pub(crate) mod log_capture;
