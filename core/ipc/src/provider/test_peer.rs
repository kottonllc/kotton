// SPDX-License-Identifier: AGPL-3.0-or-later
//! Driving the **far end** of an inherited channel, in a test.
//!
//! ## Why this is not just `read_frame`
//!
//! `channel-check` reads the tree for `read_frame::<Req, _>` call sites and
//! treats each one as *an acceptor of `Req`* (RFC-0082 rule 2: one acceptor, one
//! request type). That is the right reading of a call site in a daemon, and the
//! wrong reading of one in a test: a test standing in for the process on the
//! other side of a pipe is not a second server, it is the peer. Left to spell it
//! the ordinary way, a channel's own round-trip test makes its crate look like
//! an acceptor of the *response* type its real peer accepts — which is a channel
//! wearing one name twice, reported on a channel that has exactly one of each.
//!
//! So the peer half is named differently, and once. The alternatives were worse:
//! hand-rolling the length prefix in each test (a second copy of the wire
//! format, which is what [`super::inherited`] exists to prevent), or spelling
//! `read_frame` without its turbofish to slip past the grep, which is fooling a
//! gate rather than answering it.
//!
//! ## Why it is feature-gated
//!
//! `test-utils` is a dev-dependency feature, so a crate cannot reach this
//! without declaring it, and a real acceptor written against it would have to
//! announce itself in its manifest first. The gate stays meaningful because the
//! escape from it is not available to the code it is watching.

use super::FrameRead;
use serde::{Deserialize, Serialize};
use std::io;
use tokio::io::{AsyncRead, AsyncWrite};

/// Read one frame as the peer on the far end of a handed channel.
///
/// Same codec, same three outcomes as [`super::read_frame`] — this is that
/// function under a name that says who is calling it.
///
/// It returns the whole [`FrameRead`] rather than flattening it to "a frame or
/// nothing", which would be the cheaper signature and the wrong one: a test
/// peer that cannot tell *the far end left* from *the far end sent something it
/// refused* asserts the same thing on both, which is the defect the type exists
/// to remove (`TASK-a-refused-frame-reads-as-a-clean-exit`).
pub async fn expect_frame<T, R>(reader: &mut R) -> FrameRead<T>
where
    T: for<'de> Deserialize<'de>,
    R: AsyncRead + Unpin,
{
    super::read_frame(reader).await
}

/// Write one frame as the peer on the far end of a handed channel.
///
/// The write direction needs no separate name — `channel-check` reads only the
/// deserializing side — and it is here anyway so a test drives both halves of a
/// channel through one module rather than reaching for the serving codec for
/// half of it.
pub async fn send_frame<T, W>(writer: &mut W, value: &T) -> io::Result<()>
where
    T: Serialize,
    W: AsyncWrite + Unpin,
{
    super::write_frame(writer, value).await
}
