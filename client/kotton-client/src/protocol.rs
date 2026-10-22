// SPDX-License-Identifier: AGPL-3.0-or-later
//! The wire types, and the one place a refusal is read.
//!
//! The types themselves are re-exported from `kotton_wire::ipc`, whose definitions are
//! authoritative. What is written here is [`unexpected`] — see below.

// Re-export the canonical IPC types from kotton_wire.
// The authoritative definitions live in crates/wire/src/ipc.rs.
// This file is kept so that `use protocol::{DeviceRequest, DeviceResponse}` in
// lib.rs continues to compile without changes.
pub use kotton_wire::ipc::{UserRequest, UserResponse};

use std::io;

/// Turn a response the caller did not expect into an error that says what it was.
///
/// ## Why this exists
///
/// Measured 2026-09-11: **127 sites** in this crate match a `UserResponse`, and until
/// now 119 of them ended:
///
/// ```text
/// got => Err(crate::protocol::unexpected(got)),
/// ```
///
/// The daemon refuses in four distinct ways — [`UserResponse::NoActiveSession`],
/// [`UserResponse::NotAllowed`], [`UserResponse::NotInScope`],
/// [`UserResponse::SessionLocked`] — each naming a different remedy, and every one of
/// them arrived at the caller as the same five words. Three sites had been fixed by
/// hand; `app.rs` carries the note, *"a bare 'unexpected response' cost three debug
/// cycles here when the answer was `NoActiveSession` and the fix was one line of test
/// setup."* The other 119 were left, so the next person paid it again — most recently
/// on `kotton id add-recovery`, where the daemon had answered `NoActiveSession`
/// (the CLI had connected without authenticating) and the person read "unexpected
/// response" and went source-diving through the dispatcher for ten minutes.
///
/// This is the repository's recurring shape, in its client form: **a fact the daemon
/// stated precisely, discarded at the boundary by a hundred copies of one `_` arm.**
/// The arm is not wrong to exist — a caller genuinely cannot handle every variant —
/// it was wrong to be written a hundred times, because then no single edit can make
/// it legible.
///
/// ## What it does
///
/// Names the variant, and for the four refusals says what the caller should do about
/// it instead. A response with no remedy still gets its own name, which is what
/// `"unexpected response"` never gave anybody.
pub(crate) fn unexpected(got: UserResponse) -> io::Error {
    let text = match &got {
        // The one that cost ten minutes. The remedy is almost never "log in again";
        // it is that the caller opened an unauthenticated connection for a request
        // that is scoped to a user. Both readings are named, because the person at
        // the terminal and the person writing the call site both land here.
        UserResponse::NoActiveSession => {
            "no authenticated session on this connection for that user — run \
             `kotton login <user>` first, or, if you are calling the client, open it \
             with `KottonClient::connect_as(user)` rather than `connect()`"
                .to_owned()
        }
        // RFC-0035's floor. Not a scope miss and not retryable: the origin is bound
        // at `Authenticate` from the credential and is not caller-assertable.
        UserResponse::NotAllowed => {
            "refused at the trust floor: this connection's origin is below the \
             operation's required trust (RFC-0035). No scope re-opens it — the \
             operation has to be invoked from a local connection"
                .to_owned()
        }
        // Retryable, unlike the floor above, which is why it is worth telling apart.
        UserResponse::NotInScope => {
            "the request is outside the allow-list this connection declared at \
             `Authenticate` — reconnect without the scope, or add the variant to it"
                .to_owned()
        }
        UserResponse::SessionLocked => {
            "the session was invalidated — re-authenticate and retry".to_owned()
        }
        other => format!("unexpected response: {other:?}"),
    };
    io::Error::other(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **The ten minutes, as a test.** Each refusal has to be distinguishable from
    /// the others by reading the error — that is the entire job.
    #[test]
    fn each_refusal_says_which_one_it_is() {
        let msgs: Vec<String> = [
            UserResponse::NoActiveSession,
            UserResponse::NotAllowed,
            UserResponse::NotInScope,
            UserResponse::SessionLocked,
        ]
        .into_iter()
        .map(|r| unexpected(r).to_string())
        .collect();

        for (i, a) in msgs.iter().enumerate() {
            for b in msgs.iter().skip(i + 1) {
                assert_ne!(a, b, "two refusals read the same; that is the bug this replaces");
            }
        }
    }

    /// The session refusal points at the call site, not only at the person. The CLI
    /// bug it was found through was a `connect()` that should have been `connect_as`,
    /// and an error that only said "log in" sends the reader to the wrong place.
    #[test]
    fn the_session_refusal_names_both_remedies() {
        let msg = unexpected(UserResponse::NoActiveSession).to_string();
        assert!(msg.contains("kotton login"), "the person at the terminal");
        assert!(msg.contains("connect_as"), "the person who wrote the call site");
    }

    /// A variant with no remedy is still named. `"unexpected response"` named
    /// nothing, which is why it could stand for four different answers at once.
    #[test]
    fn a_response_with_no_remedy_is_still_named() {
        let msg = unexpected(UserResponse::UserLoggedOut).to_string();
        assert!(msg.contains("UserLoggedOut"), "got: {msg}");
    }
}
