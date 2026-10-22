// SPDX-License-Identifier: AGPL-3.0-or-later
//! Serving a channel you were **handed**, rather than one you listen on.
//!
//! ## Why this is not on `ChannelAcceptor`
//!
//! `ChannelAcceptor` binds a path and accepts. Everything that makes that safe —
//! a `0o700` directory, a check on who connected — is compensation for the
//! socket being reachable at all. A process handed one end of a `socketpair`
//! at spawn has no such surface: there is no path, so there is nobody to
//! turn away.
//!
//! That is why nothing here takes a [`crate::Caller`]. It is not an oversight
//! and `caller-check` does not apply: on a listening socket, "who is this?"
//! is a question that has to be asked, and on an inherited one it cannot be
//! posed. Possession of the channel is the authority.
//!
//! ## The transport
//!
//! Generic over `AsyncRead`/`AsyncWrite` rather than taking a socket, for one
//! reason that matters: the child cannot rebuild a socket from a file
//! descriptor without `unsafe`, which this workspace denies. So the parent
//! passes its end as *both* stdin and stdout and the child frames over
//! `tokio::io::stdin()` / `stdout()` — the same shape the guest runner
//! (channel 4) has always used. Being generic also lets the round-trip test
//! drive a real `socketpair` directly, without a process.
//!
//! Frames are the same 4-byte little-endian length prefix and JSON body that
//! `ChannelAcceptor` uses, so a peer cannot tell which of the two is on the far end.

use serde::{Deserialize, Serialize};
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Frames larger than this are refused before allocating. Matches `ChannelAcceptor`.
///
/// Public because it is a fact about the wire rather than about this function:
/// a test that plants an over-cap length header has to know where the cap is,
/// and one that hard-codes a number of its own goes quietly stale the day the
/// cap moves. Both ends of every inherited channel already share it.
pub const MAX_FRAME_LEN: usize = 32 * 1024 * 1024;

/// Serve requests over an inherited channel until the far end closes it.
///
/// Returns `Ok(())` on a clean EOF — for a channel handed over at spawn, the
/// peer going away is the normal end of the conversation, not an error.
///
/// A [`Refusal`] is the other thing, and it returns `Err`. The two were one
/// return value until 2026-09-15 and the cost is written on [`read_frame`].
///
/// **A handler's `Err` is answered, and the channel keeps serving.**
/// `Resp: From<io::Error>` is the same bound `ChannelAcceptor` takes, for the
/// same reason: the channel's vocabulary says what an error reads as, and the
/// one loop that would otherwise drop it says it instead of each handler
/// mapping its own. Unlike the acceptor, this end does not close after the
/// frame. A handed-over channel has one peer for its whole life, so closing it
/// would end the only conversation there is over one request that failed —
/// and a handler's error is about that request, not about the channel. What
/// ends the channel is still what always did: the peer leaving, a
/// [`Refusal`], or a write that cannot reach it. Until 2026-09-28 a `?` here
/// ended it with nothing said
/// (`TASK-an-inherited-channel-ends-on-a-handlers-first-error`).
pub async fn serve_inherited<Req, Resp, R, W, F, Fut>(
    mut reader: R,
    mut writer: W,
    mut handler: F,
) -> io::Result<()>
where
    Req: for<'de> Deserialize<'de>,
    Resp: Serialize + From<io::Error>,
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
    F: FnMut(Req) -> Fut,
    Fut: std::future::Future<Output = io::Result<Resp>>,
{
    loop {
        let request = match read_frame::<Req, _>(&mut reader).await {
            FrameRead::Frame(request) => request,
            // The peer went away. For a channel handed over at spawn that is
            // how the conversation ends.
            FrameRead::EndOfStream => return Ok(()),
            // The peer is still there and said something this end will not
            // accept. Reported, never mistaken for departure.
            FrameRead::Refused(refusal) => return Err(refusal.into()),
        };

        // What the log may say of it is one rule for both doors:
        // `answer_for_a_handlers_error`.
        let response = handler(request)
            .await
            .unwrap_or_else(|e| super::answer_for_a_handlers_error("inherited channel", e));

        if write_frame(&mut writer, &response).await.is_err() {
            return Ok(());
        }
    }
}

/// What one read of an inherited channel produced.
///
/// Three kinds of ending, because there are three things that can happen and
/// only two of them are the same kind of event. Before 2026-09-15 this was an
/// `Option<T>`, and `None` meant *end of stream*, *over the length cap* and
/// *undecodable body* alike — so no caller could tell **peer-gone** from
/// **protocol-broken**, and every caller chose one meaning for both. The one
/// that chose "gone" is how a single bad byte switched `kinferd` off for the
/// daemon's lifetime with nothing recorded anywhere
/// (`TASK-a-refused-frame-reads-as-a-clean-exit`).
///
/// There is deliberately no `fn frame(self) -> Option<T>` here. A helper that
/// folds the two terminal arms back together is the defect this type exists to
/// remove, and it would be one line away from every call site.
#[derive(Debug)]
#[must_use]
pub enum FrameRead<T> {
    /// A frame arrived and decoded.
    Frame(T),
    /// The far end closed between frames. For a channel handed over at spawn
    /// this is the normal end of the conversation and not a fault.
    EndOfStream,
    /// The far end said something this end will not accept. Terminal in the
    /// same way end-of-stream is — on a channel only two processes hold, a bad
    /// frame means they disagree about the protocol and continuing would mean
    /// guessing which of them is wrong — but it is **not the same event**, and
    /// a caller that reports it as one is reporting a break as a goodbye.
    Refused(Refusal),
}

/// Why a frame was refused. Carried so the refusal can be *named* where it is
/// reported: a sidecar writes it to stderr before exiting non-zero, and its
/// supervisor records what it read there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// The length header announced more than [`MAX_FRAME_LEN`]. Refused before
    /// a byte of it is allocated, which is the whole reason the cap is checked
    /// on the header rather than after the read.
    OverLength {
        /// What the header claimed, so the report can say how far over it was.
        len: usize,
    },
    /// The body arrived whole and was not a value of the expected type.
    ///
    /// **Carries where and what kind, and nothing the frame said.** The obvious
    /// field here is `serde_json::Error`'s own message, and it is the wrong one:
    /// that message quotes the input back — `unknown variant \`…\``,
    /// `unknown field \`…\`` — and the input on these channels is a person's
    /// question and the passages selected to answer it. RFC-0085 IN9 says no
    /// prompt, passage or answer appears in any log or diagnostic, and a refusal
    /// is written to stderr, recorded by a supervisor and shown by
    /// `kotton sidecars`. A position and a category say the same thing to
    /// whoever is debugging two ends of one type, and say nothing about what was
    /// in the frame.
    Undecodable {
        /// `serde_json`'s own category: `syntax`, `data`, `eof` or `io`.
        kind: &'static str,
        /// 1-based line the decoder stopped at.
        line: usize,
        /// 1-based column the decoder stopped at.
        column: usize,
    },
    /// The header promised `expected` bytes and the far end closed before they
    /// arrived. Not end-of-stream: a peer that closes *between* frames has left,
    /// and a peer that closes *inside* one has broken the frame it was writing.
    TruncatedBody {
        /// What the header promised.
        expected: usize,
    },
    /// The far end went away part-way through the four-byte length prefix.
    ///
    /// The same distinction as [`Refusal::TruncatedBody`], one step earlier, and
    /// it needs its own arm because a peer one byte into a header has *started a
    /// frame*: leaving then is a break, and calling it departure is the defect
    /// this type exists to remove, reintroduced at the one place `read_exact`
    /// cannot tell the two apart — it returns the same `UnexpectedEof` for
    /// nothing-read and something-read.
    ///
    /// **What is folded here, stated rather than implied:** an I/O error is read
    /// as the peer going away, at both this arm and
    /// [`Refusal::TruncatedBody`]. So "how many bytes had arrived" is the
    /// distinction being drawn, and "clean close or broken pipe" is not — a
    /// channel that errors mid-frame and one that closes mid-frame have both
    /// broken the frame, and neither this end nor its caller can do anything
    /// different about them.
    TruncatedHeader {
        /// How many of the four bytes arrived. Never zero: at zero, the peer had
        /// not started a frame, and that is [`FrameRead::EndOfStream`].
        got: usize,
    },
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Refusal::OverLength { len } => write!(
                f,
                "refused frame: length header of {len} bytes exceeds the {MAX_FRAME_LEN}-byte frame ceiling"
            ),
            Refusal::Undecodable { kind, line, column } => write!(
                f,
                "refused frame: undecodable body ({kind}) at line {line} column {column}"
            ),
            Refusal::TruncatedBody { expected } => write!(
                f,
                "refused frame: the far end closed inside a frame of {expected} bytes"
            ),
            Refusal::TruncatedHeader { got } => write!(
                f,
                "refused frame: the far end closed after {got} of 4 length bytes"
            ),
        }
    }
}

impl From<Refusal> for io::Error {
    /// `InvalidData` in every arm: the bytes were the problem, not the pipe.
    fn from(refusal: Refusal) -> Self {
        io::Error::new(io::ErrorKind::InvalidData, refusal.to_string())
    }
}

/// Read one length-prefixed JSON frame.
///
/// Returns which of the three kinds of ending happened — see [`FrameRead`].
/// All of them stop the channel; what differs is whether there is anyone to
/// report to and anything to report.
///
/// Extracted from [`serve_inherited`] when kuserd's surface proxy needed the
/// same codec to read a direction it does not serve. A second hand-rolled copy
/// of a wire format is how two ends of one channel start to differ.
pub async fn read_frame<T, R>(reader: &mut R) -> FrameRead<T>
where
    T: for<'de> Deserialize<'de>,
    R: AsyncRead + Unpin,
{
    // Read the length prefix by hand rather than with `read_exact`, for the one
    // thing `read_exact` cannot say: whether *any* of it arrived. It reports the
    // same `UnexpectedEof` for a peer that closed between frames and one that
    // closed one byte into the next — and those are the two outcomes this whole
    // type exists to keep apart.
    //
    // A read error and a clean close are *not* kept apart, deliberately: both
    // mean nothing more is coming, and what decides the answer is how far into a
    // frame the peer had got when it stopped. See `Refusal::TruncatedHeader`.
    let mut len_bytes = [0u8; 4];
    let mut got = 0usize;
    while got < 4 {
        match reader.read(&mut len_bytes[got..]).await {
            // Nothing more is coming. Zero bytes in is the peer leaving between
            // frames, which for an inherited channel is the normal ending.
            Ok(0) | Err(_) => {
                if got == 0 {
                    return FrameRead::EndOfStream;
                }
                tracing::warn!(got, "inherited channel: length prefix truncated; refusing");
                return FrameRead::Refused(Refusal::TruncatedHeader { got });
            }
            Ok(n) => got += n,
        }
    }
    let len = u32::from_le_bytes(len_bytes) as usize;

    if len > MAX_FRAME_LEN {
        // Logged here as well as returned: this end knows the number, and the
        // caller decides what to do about it. Nothing of the body is read, so
        // the channel is desynchronised from here on and the only sound move is
        // the one every caller makes — stop.
        tracing::warn!(len, "inherited channel: frame exceeds MAX_FRAME_LEN; refusing");
        return FrameRead::Refused(Refusal::OverLength { len });
    }

    let mut buffer = vec![0u8; len];
    if reader.read_exact(&mut buffer).await.is_err() {
        tracing::warn!(len, "inherited channel: frame truncated; refusing");
        return FrameRead::Refused(Refusal::TruncatedBody { expected: len });
    }

    match serde_json::from_slice(&buffer) {
        Ok(v) => FrameRead::Frame(v),
        Err(e) => {
            // `e` itself is never logged, here or anywhere it is handed on: its
            // message quotes the frame back. See [`Refusal::Undecodable`].
            let refusal = Refusal::Undecodable {
                kind: category_of(&e),
                line: e.line(),
                column: e.column(),
            };
            tracing::warn!(%refusal, "inherited channel: undecodable frame; refusing");
            FrameRead::Refused(refusal)
        }
    }
}

/// `serde_json`'s category as a fixed word, so nothing from the frame is
/// carried out with it.
fn category_of(e: &serde_json::Error) -> &'static str {
    use serde_json::error::Category;
    match e.classify() {
        Category::Io => "io",
        Category::Syntax => "syntax",
        Category::Data => "data",
        Category::Eof => "eof",
    }
}

/// Write one length-prefixed JSON frame and flush it.
pub async fn write_frame<T, W>(writer: &mut W, value: &T) -> io::Result<()>
where
    T: Serialize,
    W: AsyncWrite + Unpin,
{
    let json = serde_json::to_vec(value)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let mut msg = Vec::with_capacity(4 + json.len());
    msg.extend_from_slice(&(json.len() as u32).to_le_bytes());
    msg.extend_from_slice(&json);

    writer.write_all(&msg).await?;
    writer.flush().await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    enum Req {
        Ping { n: u32 },
        Fail,
    }

    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    enum Resp {
        Pong { n: u32 },
        Error { message: String },
    }

    impl From<io::Error> for Resp {
        fn from(e: io::Error) -> Self {
            Resp::Error {
                message: e.to_string(),
            }
        }
    }

    /// The handler every served test uses: `Ping` answers, `Fail` errs.
    async fn ping(req: Req) -> io::Result<Resp> {
        match req {
            Req::Ping { n } => Ok(Resp::Pong { n: n + 1 }),
            Req::Fail => Err(io::Error::other("the handler could not do that")),
        }
    }

    async fn send_frame<W: AsyncWrite + Unpin>(w: &mut W, req: &Req) {
        let json = serde_json::to_vec(req).expect("encode");
        let mut msg = (json.len() as u32).to_le_bytes().to_vec();
        msg.extend_from_slice(&json);
        w.write_all(&msg).await.expect("write");
        w.flush().await.expect("flush");
    }

    /// Every read here is bounded.
    ///
    /// Both of these tests were first written unbounded, and planting a
    /// violation showed why that is wrong: a server that stops replying made
    /// them **hang** rather than fail. A hanging test burns its harness timeout
    /// and gets reported as an infrastructure problem instead of the assertion
    /// it actually is.
    const PATIENCE: std::time::Duration = std::time::Duration::from_secs(5);

    async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> Resp {
        let mut len = [0u8; 4];
        tokio::time::timeout(PATIENCE, r.read_exact(&mut len))
            .await
            .expect("timed out waiting for a response frame")
            .expect("len");
        let mut buf = vec![0u8; u32::from_le_bytes(len) as usize];
        tokio::time::timeout(PATIENCE, r.read_exact(&mut buf))
            .await
            .expect("timed out reading a response body")
            .expect("body");
        serde_json::from_slice(&buf).expect("decode")
    }

    /// A real `socketpair` round trip, with no path and no listener anywhere.
    ///
    /// This is the coverage the kuid transport did not have: `kuid_surface.rs`
    /// tests the sidecar map and the env var, so nothing exercised a live
    /// request over the wire kuid actually uses.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_handed_over_channel_round_trips() {
        let (ours, theirs) = tokio::net::UnixStream::pair().expect("socketpair");
        let (their_r, their_w) = theirs.into_split();

        let served = tokio::spawn(async move {
            serve_inherited::<Req, Resp, _, _, _, _>(their_r, their_w, ping).await
        });

        let (mut our_r, mut our_w) = ours.into_split();
        for n in [1u32, 7, 4242] {
            send_frame(&mut our_w, &Req::Ping { n }).await;
            assert_eq!(read_frame(&mut our_r).await, Resp::Pong { n: n + 1 });
        }

        // Dropping our end is how the conversation ends, and it must be a
        // clean return rather than an error: for an inherited channel the peer
        // going away is the normal case.
        drop(our_w);
        drop(our_r);
        tokio::time::timeout(PATIENCE, served)
            .await
            .expect("the server should return once our end is dropped")
            .expect("join")
            .expect("clean EOF, not an error");
    }

    /// A handler's `Err` is answered with a frame carrying its text, and the
    /// channel **stays open**: the next request is served.
    ///
    /// Until 2026-09-28 the `?` on the handler returned from `serve_inherited`,
    /// so the peer read an end of stream with nothing said — and on a channel
    /// handed over at spawn that is the only connection there will ever be
    /// (`TASK-an-inherited-channel-ends-on-a-handlers-first-error`). The
    /// second request is what tells "answered and kept serving" from the
    /// acceptor's "answered and closed", which would be wrong here.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_handlers_error_is_answered_and_the_channel_keeps_serving() {
        let (ours, theirs) = tokio::net::UnixStream::pair().expect("socketpair");
        let (their_r, their_w) = theirs.into_split();

        let served = tokio::spawn(async move {
            serve_inherited::<Req, Resp, _, _, _, _>(their_r, their_w, ping).await
        });

        let (mut our_r, mut our_w) = ours.into_split();
        send_frame(&mut our_w, &Req::Fail).await;
        assert_eq!(
            read_frame(&mut our_r).await,
            Resp::Error {
                message: "the handler could not do that".into()
            },
            "the error is said, in the channel's own error frame",
        );

        send_frame(&mut our_w, &Req::Ping { n: 41 }).await;
        assert_eq!(
            read_frame(&mut our_r).await,
            Resp::Pong { n: 42 },
            "the one peer this channel has is still being served",
        );

        drop(our_w);
        drop(our_r);
        tokio::time::timeout(PATIENCE, served)
            .await
            .expect("the server should return once our end is dropped")
            .expect("join")
            .expect("a handler's error is not the channel's: clean EOF");
    }

    /// **The log says a handler failed and how, and not in what words** — the
    /// same rule, reached the same way, as the acceptor's
    /// `a_handlers_error_text_reaches_the_client_and_not_the_log`
    /// (`TASK-the-two-ipc-doors-log-a-handlers-error-differently`).
    #[cfg(unix)]
    #[tokio::test]
    async fn a_handlers_error_text_reaches_the_peer_and_not_the_log() {
        let capture = crate::provider::log_capture::Capture::start();
        let (ours, theirs) = tokio::net::UnixStream::pair().expect("socketpair");
        let (their_r, their_w) = theirs.into_split();
        let served = tokio::spawn(async move {
            serve_inherited::<Req, Resp, _, _, _, _>(their_r, their_w, ping).await
        });

        let (mut our_r, mut our_w) = ours.into_split();
        send_frame(&mut our_w, &Req::Fail).await;
        assert_eq!(
            read_frame(&mut our_r).await,
            Resp::Error {
                message: "the handler could not do that".into()
            },
            "the words reach the peer",
        );
        drop(our_w);
        drop(our_r);
        tokio::time::timeout(PATIENCE, served)
            .await
            .expect("returns once our end is dropped")
            .expect("join")
            .expect("clean EOF");

        let lines = capture.lines();
        let failed: Vec<_> = lines.iter().filter(|l| l.contains("handler failed")).collect();
        assert_eq!(failed.len(), 1, "one line for one error: {lines:?}");
        assert!(failed[0].contains("kind=Other"), "the kind is logged: {failed:?}");
        assert!(
            lines.iter().all(|l| !l.contains("could not do that")),
            "the handler's words reached the log: {lines:?}"
        );
    }

    /// A frame the far end cannot parse closes the channel instead of being
    /// answered — the two sides disagree about the protocol, and there is no
    /// third party who could be at fault.
    ///
    /// And it **returns the refusal**, where until 2026-09-15 it returned
    /// `Ok(())`: the caller of this helper is a process whose exit code is the
    /// only thing its supervisor reads, and `Ok` there is a clean exit.
    #[cfg(unix)]
    #[tokio::test]
    async fn an_undecodable_frame_ends_the_conversation() {
        let (ours, theirs) = tokio::net::UnixStream::pair().expect("socketpair");
        let (their_r, their_w) = theirs.into_split();

        let served = tokio::spawn(async move {
            serve_inherited::<Req, Resp, _, _, _, _>(their_r, their_w, ping).await
        });

        let (mut our_r, mut our_w) = ours.into_split();
        let junk = b"{\"NotAVariant\":{}}";
        let mut msg = (junk.len() as u32).to_le_bytes().to_vec();
        msg.extend_from_slice(junk);
        our_w.write_all(&msg).await.expect("write");
        our_w.flush().await.expect("flush");

        let outcome = tokio::time::timeout(PATIENCE, served)
            .await
            .expect("the server should close on an undecodable frame, not wait for more")
            .expect("join");
        let err = outcome.expect_err("a refused frame is not a clean stop");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(
            err.to_string().contains("undecodable"),
            "the refusal has to name its cause: {err}"
        );

        // Nothing came back, and the channel is shut.
        let mut buf = [0u8; 1];
        assert_eq!(
            tokio::time::timeout(PATIENCE, our_r.read(&mut buf))
                .await
                .expect("timed out confirming the far end closed")
                .expect("read after close"),
            0,
            "the far end should have closed rather than replied",
        );
    }

    /// Departure has exactly one shape — nothing at all — and every other way
    /// a read can end is a refusal that names itself. Read directly rather than
    /// through `serve_inherited`, so what is asserted is the codec's own
    /// verdict.
    #[tokio::test]
    async fn departure_is_told_from_every_kind_of_break() {
        // Nothing at all: the peer closed between frames, which is departure.
        let mut empty: &[u8] = &[];
        assert!(matches!(
            super::read_frame::<Req, _>(&mut empty).await,
            FrameRead::EndOfStream
        ));

        // A length header over the cap, and no body behind it. This is the
        // cheap shape of the attack: four bytes make the far end refuse, and
        // nothing is allocated on the way.
        let over = 33 * 1024 * 1024usize;
        assert!(
            over > MAX_FRAME_LEN,
            "this test's header must be over the cap it is testing"
        );
        let header_bytes = (over as u32).to_le_bytes();
        let mut header: &[u8] = &header_bytes;
        match super::read_frame::<Req, _>(&mut header).await {
            FrameRead::Refused(Refusal::OverLength { len }) => assert_eq!(len, over),
            other => panic!("expected an over-length refusal, got {other:?}"),
        }

        // A whole body that is not a `Req`.
        let junk = br#"{"NotAVariant":{}}"#;
        let mut framed = (junk.len() as u32).to_le_bytes().to_vec();
        framed.extend_from_slice(junk);
        let mut framed: &[u8] = &framed;
        match super::read_frame::<Req, _>(&mut framed).await {
            FrameRead::Refused(Refusal::Undecodable { kind, line, column }) => {
                // `data`, not `syntax`: the JSON parsed and was not a `Req`.
                assert_eq!(kind, "data");
                assert!(line >= 1 && column >= 1, "a position, not a quotation");
            }
            other => panic!("expected an undecodable refusal, got {other:?}"),
        }

        // A header promising more than the peer then sent. A peer that closes
        // *inside* a frame did not leave between frames.
        let mut truncated: &[u8] = &[8, 0, 0, 0, b'{'];
        match super::read_frame::<Req, _>(&mut truncated).await {
            FrameRead::Refused(Refusal::TruncatedBody { expected }) => assert_eq!(expected, 8),
            other => panic!("expected a truncated-body refusal, got {other:?}"),
        }

        // Two bytes of a four-byte header. The peer had started a frame, so
        // this is a break and not a goodbye — and it is the one case
        // `read_exact` reports identically to the empty reader above.
        let mut half_header: &[u8] = &[8, 0];
        match super::read_frame::<Req, _>(&mut half_header).await {
            FrameRead::Refused(Refusal::TruncatedHeader { got }) => assert_eq!(got, 2),
            other => panic!("expected a truncated-header refusal, got {other:?}"),
        }
    }

    /// Every refusal says what it was, in words a supervisor can record.
    #[test]
    fn a_refusal_names_its_cause() {
        assert!(Refusal::OverLength { len: 34_603_008 }
            .to_string()
            .contains("34603008"));
        let undecodable = Refusal::Undecodable {
            kind: "data",
            line: 1,
            column: 15,
        }
        .to_string();
        assert!(undecodable.contains("undecodable"));
        assert!(undecodable.contains("line 1 column 15"));
        assert!(Refusal::TruncatedBody { expected: 8 }
            .to_string()
            .contains("closed inside a frame"));
        assert!(Refusal::TruncatedHeader { got: 2 }
            .to_string()
            .contains("2 of 4 length bytes"));
        // And it is `InvalidData` when it becomes an `io::Error`: the bytes
        // were the problem, not the pipe.
        let e: io::Error = Refusal::OverLength { len: 1 }.into();
        assert_eq!(e.kind(), io::ErrorKind::InvalidData);
    }
}
