// SPDX-License-Identifier: AGPL-3.0-or-later
use crate::{Caller, OsListener, PeerUsers};
use kotton_sys::ipc::IpcEndpoint;
use kotton_sys::ipc::Connection;
use serde::{Deserialize, Serialize};
use std::io;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

/// Maximum IPC frame length (32 MiB).
///
/// After reading the 4-byte length prefix we check it against this limit
/// *before* allocating the receive buffer. This prevents a malicious or
/// buggy client from triggering a 4 GiB allocation. The value is large
/// enough to accommodate any `AppInstall` WASM binary we'd accept;
/// normal requests are orders of magnitude smaller.
const MAX_FRAME_LEN: usize = 32 * 1024 * 1024;

/// Binds a path and accepts connections on one channel.
///
/// Named for what it does. It was `IpcServer` until 2026-08-24, and the name was
/// the tell: it does not route, multiplex, or manage sessions, so "server"
/// described a shape nobody had checked it had. What it is is the *accepting*
/// half of one channel — `Req` and `Resp` are that channel's vocabulary, and
/// RFC-0082 rule 2 holds that no other acceptor deserializes the same `Req`.
///
/// The counterpart is [`crate::serve_inherited`], for a channel handed over at
/// spawn rather than found at a path. That one takes no [`crate::Caller`],
/// because a channel nobody else can reach has nobody to identify. It answers a
/// handler's error with the same `Resp: From<io::Error>` frame and, having one
/// peer for life, keeps serving where this one closes
/// (`TASK-an-inherited-channel-ends-on-a-handlers-first-error`). This one
/// always does: an acceptor that wants no identity says so by ignoring the
/// argument, in its own source, where a reviewer sees it. It cannot get there
/// by picking a shorter method name — that is how `accept_authenticated` came
/// to have zero call sites, and `caller-check` holds it. A channel with nothing
/// to check still receives a [`Caller`], [`Caller::anonymous`] where the
/// platform supplied nothing.
///
/// **A handler's `Err` is answered, never dropped.** `Resp: From<io::Error>` is
/// how a channel's vocabulary says what an error reads as, and the acceptor
/// writes that frame before it closes the connection. Until 2026-09-28 it
/// closed with nothing said, so every `?` in every door's handler reached the
/// person at the other end as a stream that ended
/// (`TASK-an-ipc-door-answers-a-handlers-error-by-closing-with-nothing-said`).
/// The rule is here rather than in each door because the acceptor is what
/// dropped the error: three doors mapping their own `Err` is three copies,
/// and the fourth door's handler would forget. A `Resp` that cannot say an
/// error does not compile here.
///
/// The connection still closes after the error frame, as it did before the
/// frame existed: a streaming client reads until the stream ends, and one
/// that does not know the error frame must still see the end it always saw
/// rather than wait on a connection the door is holding open.
///
/// **A door admits only the OS users it names, at accept.** [`Self::listen`] takes
/// the door's [`PeerUsers`], and each connection whose peer the kernel does not
/// name as one of them is closed as it is accepted: before a frame is read, with
/// no reply, and the handler never sees it. The rule is here, once, so kdeviced's,
/// kuserd's and kvaultd's doors hold it alike; a door says which users it admits in
/// its own source, where a reviewer sees it. On Windows the pipe's caller is not
/// held to it here.
pub struct ChannelAcceptor<Req, Resp> {
    listener: OsListener,
    #[cfg(unix)]
    admits: PeerUsers,
    _phantom: std::marker::PhantomData<(Req, Resp)>,
}

impl<Req, Resp> ChannelAcceptor<Req, Resp>
where
    Req: for<'de> Deserialize<'de>,
    Resp: Serialize + From<io::Error>,
{
    /// Bind the endpoint, admitting connections only from `admits`. Off Unix the
    /// acceptor holds no user set and admits every peer, as [`PeerUsers`] says.
    #[cfg_attr(not(unix), allow(unused_variables))]
    pub async fn listen(endpoint: IpcEndpoint, admits: PeerUsers) -> io::Result<Self> {
        let listener = OsListener::bind(endpoint)
            .await
            .map_err(io::Error::other)?;
        Ok(Self {
            listener,
            #[cfg(unix)]
            admits,
            _phantom: std::marker::PhantomData,
        })
    }

    /// Whether this door admits `peer` ([`PeerUsers::require`]). A refusal is
    /// logged with who it was, and the caller closes the connection unread.
    #[cfg_attr(not(unix), allow(unused_variables))]
    fn admits(&self, peer: &Caller) -> bool {
        #[cfg(unix)]
        if let Err(e) = self.admits.require(peer) {
            tracing::warn!(refused = %e, "a connection was closed at accept, unread");
            return false;
        }
        true
    }

    pub async fn accept_with_session<F, Fut, S>(&self, handler: F) -> io::Result<()>
    where
        F: Fn(Req, Caller, Arc<Mutex<Option<S>>>) -> Fut + Clone + Send + 'static,
        Fut: std::future::Future<Output = io::Result<Resp>> + Send + 'static,
        Req: for<'de> Deserialize<'de> + Send + 'static,
        Resp: Serialize + Send + 'static,
        S: Send + 'static,
    {
        loop {
            let accepted = self
                .listener
                .accept_with_peer()
                .await
                .map_err(io::Error::other)?;

            // Closed here, by dropping it, before anything is read or written.
            if !self.admits(&accepted.peer) {
                continue;
            }
            let mut connection = accepted.connection;
            let peer = accepted.peer;
            let handler = handler.clone();

            tokio::spawn(async move {
                // The per-connection session slot. `S` is the caller's own state
                // type — `String` for a token, or a typed enum where the classes
                // a handler must tell apart deserve to be variants the compiler
                // checks (kdeviced's principal classes, Article II).
                let conn_session: Arc<Mutex<Option<S>>> = Arc::new(Mutex::new(None));

                loop {
                    let mut len_bytes = [0u8; 4];
                    if read_exact(&mut *connection, &mut len_bytes).await.is_err() {
                        break;
                    }
                    let len = u32::from_le_bytes(len_bytes) as usize;

                    if len > MAX_FRAME_LEN {
                        tracing::warn!(len, "IPC frame exceeds MAX_FRAME_LEN; closing connection");
                        break;
                    }

                    let mut buffer = vec![0u8; len];
                    if read_exact(&mut *connection, &mut buffer).await.is_err() {
                        break;
                    }

                    let request: Req = match serde_json::from_slice(&buffer) {
                        Ok(r) => r,
                        Err(_) => break,
                    };

                    match handler(request, peer.clone(), Arc::clone(&conn_session)).await {
                        Ok(response) => {
                            let Ok(msg) = frame(&response) else { break };
                            if write_all(&mut *connection, &msg).await.is_err() {
                                break;
                            }
                        }
                        Err(e) => {
                            answer_error::<Resp>(&mut *connection, e).await;
                            break;
                        }
                    }
                }
            });
        }
    }
}

/// The return value of a streaming-capable request handler.
///
/// Most requests return [`HandlerOutput::Single`] (the existing one-shot
/// request/response pattern).  A handler returns [`HandlerOutput::Stream`]
/// when it wants to write an unbounded sequence of frames — e.g.
/// `SubscribeEvents`.  After the stream channel closes the connection is
/// terminated gracefully by the server.
pub enum HandlerOutput<Resp> {
    /// Normal single-frame response.
    Single(Resp),
    /// Streaming: receive frames from `rx` and forward them to the client
    /// until the sender is dropped.
    Stream(mpsc::Receiver<Resp>),
}

impl<Resp> HandlerOutput<Resp> {
    /// This answer as a stream that ends: a `Stream` as it is, and a `Single`
    /// as its one frame and then the end.
    ///
    /// **A request its client reads as a stream is answered as one, whatever
    /// it says.** [`crate::IpcClient::send_streaming`] reads frames until the
    /// door closes the connection, and the door closes it only after a
    /// `Stream`: after a `Single` it waits for the next request on the same
    /// connection, which a streaming client never sends. So a `Single`
    /// answering a streaming request leaves both sides waiting, and the client
    /// can end only by guessing which frames are last (#112). A handler for
    /// such a request answers through this, and its client's `recv` returns
    /// `None` after the one frame.
    pub fn into_stream(self) -> mpsc::Receiver<Resp> {
        match self {
            Self::Stream(rx) => rx,
            Self::Single(frame) => {
                let (tx, rx) = mpsc::channel(1);
                // One frame into an empty channel of one: it is taken, and the
                // sender dropped here is the stream's end.
                let _ = tx.try_send(frame);
                rx
            }
        }
    }
}

impl<Req, Resp> ChannelAcceptor<Req, Resp>
where
    Req: for<'de> Deserialize<'de>,
    Resp: Serialize + From<io::Error>,
{
    /// Like [`Self::accept_with_session`] but supports both single-frame and
    /// streaming responses.
    ///
    /// The handler returns [`HandlerOutput`]:
    /// - [`HandlerOutput::Single`]: the server writes one response frame and
    ///   loops back to read the next request (identical to `accept_with_session`).
    /// - [`HandlerOutput::Stream`]: the server drains the channel, writing one
    ///   frame per item, then terminates the connection when the channel closes.
    ///
    /// The session slot type `S` is caller-defined. A fresh `Arc<Mutex<Option<S>>>`
    /// is created for each accepted connection. `S = String` gives the simple
    /// token-only behaviour of `accept_with_session`; callers can use a richer
    /// struct to store additional per-connection state (e.g. a scope allow-list).
    pub async fn accept_with_session_streaming<F, Fut, S>(&self, handler: F) -> io::Result<()>
    where
        F: Fn(Req, Caller, Arc<Mutex<Option<S>>>) -> Fut + Clone + Send + 'static,
        Fut: std::future::Future<Output = io::Result<HandlerOutput<Resp>>> + Send + 'static,
        Req: for<'de> Deserialize<'de> + Send + 'static,
        Resp: Serialize + Send + Sync + 'static,
        S: Send + 'static,
    {
        loop {
            let accepted = self
                .listener
                .accept_with_peer()
                .await
                .map_err(io::Error::other)?;

            // Closed here, by dropping it, before anything is read or written.
            if !self.admits(&accepted.peer) {
                continue;
            }
            let mut connection = accepted.connection;
            let peer = accepted.peer;
            let handler = handler.clone();

            tokio::spawn(async move {
                let conn_session: Arc<Mutex<Option<S>>> = Arc::new(Mutex::new(None));

                loop {
                    let mut len_bytes = [0u8; 4];
                    if read_exact(&mut *connection, &mut len_bytes).await.is_err() {
                        break;
                    }
                    let len = u32::from_le_bytes(len_bytes) as usize;

                    if len > MAX_FRAME_LEN {
                        tracing::warn!(len, "IPC frame exceeds MAX_FRAME_LEN; closing connection");
                        break;
                    }

                    let mut buffer = vec![0u8; len];
                    if read_exact(&mut *connection, &mut buffer).await.is_err() {
                        break;
                    }

                    let request: Req = match serde_json::from_slice(&buffer) {
                        Ok(r) => r,
                        Err(_) => break,
                    };

                    match handler(request, peer.clone(), Arc::clone(&conn_session)).await {
                        Ok(HandlerOutput::Single(resp)) => {
                            if write_frame(&mut *connection, &resp).await.is_err() {
                                break;
                            }
                        }
                        Ok(HandlerOutput::Stream(mut rx)) => {
                            // Drain the stream — one frame per item.
                            while let Some(frame) = rx.recv().await {
                                if write_frame(&mut *connection, &frame).await.is_err() {
                                    break;
                                }
                            }
                            // Stream ended — close connection.
                            break;
                        }
                        Err(e) => {
                            answer_error::<Resp>(&mut *connection, e).await;
                            break;
                        }
                    }
                }
            });
        }
    }
}

/// Say a handler's error to the client, in the channel's own error frame.
///
/// Best-effort: a client already gone cannot be told, and the connection
/// closes either way. What the log may say of the error is one rule for both
/// doors, and it lives on [`super::answer_for_a_handlers_error`].
async fn answer_error<Resp: Serialize + From<io::Error>>(conn: &mut dyn Connection, e: io::Error) {
    // Serialized before the await, so no `&Resp` is held across it and `Resp`
    // need not be `Sync`.
    let msg = frame(&super::answer_for_a_handlers_error::<Resp>("IPC door", e));
    if let Ok(msg) = msg {
        let _ = write_all(conn, &msg).await;
    }
}

/// `resp` serialized as a length-prefixed frame.
fn frame<Resp: Serialize>(resp: &Resp) -> io::Result<Vec<u8>> {
    let json =
        serde_json::to_vec(resp).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let len = json.len() as u32;
    let mut msg = Vec::with_capacity(4 + json.len());
    msg.extend_from_slice(&len.to_le_bytes());
    msg.extend_from_slice(&json);
    Ok(msg)
}

/// Serialize `resp` and write it as a length-prefixed frame.
async fn write_frame<Resp: Serialize>(conn: &mut dyn Connection, resp: &Resp) -> io::Result<()> {
    write_all(conn, &frame(resp)?).await
}

/// Helper to read exact number of bytes
async fn read_exact(conn: &mut dyn Connection, buf: &mut [u8]) -> io::Result<()> {
    let mut read = 0;
    while read < buf.len() {
        let n = conn
            .read(&mut buf[read..])
            .await
            .map_err(|e| io::Error::other(e.to_string()))?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "connection closed",
            ));
        }
        read += n;
    }
    Ok(())
}

/// Helper to write all bytes
async fn write_all(conn: &mut dyn Connection, buf: &[u8]) -> io::Result<()> {
    let mut written = 0;
    while written < buf.len() {
        let n = conn
            .write(&buf[written..])
            .await
            .map_err(|e| io::Error::other(e.to_string()))?;
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::WriteZero, "write zero bytes"));
        }
        written += n;
    }
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::IpcClient;
    use std::time::Duration;

    #[derive(Serialize, Deserialize, Debug)]
    enum Req {
        Fail,
        Ping,
    }

    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    enum Resp {
        Pong,
        Error { message: String },
    }

    impl From<io::Error> for Resp {
        fn from(e: io::Error) -> Self {
            Resp::Error {
                message: e.to_string(),
            }
        }
    }

    /// A socket in a directory under `/tmp` that the test makes and that goes
    /// when the guard drops. Joined onto `TMPDIR`, whose length no test sets,
    /// all three tests here failed `SUN_LEN` under a 104-byte one, and each run
    /// left its directory behind (`TASK-three-unit-tests-join-their-socket-onto-tmpdir-by-hand`).
    fn a_socket() -> (tempfile::TempDir, IpcEndpoint) {
        let dir = crate::provider::os::tests::socket_dir();
        let endpoint = IpcEndpoint::UnixSocket(dir.path().join("sock"));
        (dir, endpoint)
    }

    async fn a_client(endpoint: &IpcEndpoint) -> IpcClient<Req, Resp> {
        for _ in 0..100 {
            if let Ok(c) = IpcClient::connect_to_own_user(endpoint.clone()).await {
                return c;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("the acceptor never listened");
    }

    fn refusal() -> io::Error {
        io::Error::other("the handler refused, in these words")
    }

    /// **A one-frame door answers a handler's `Err` in the error's words, then
    /// closes** — the path kdeviced's system socket is served through
    /// (`TASK-an-ipc-door-answers-a-handlers-error-by-closing-with-nothing-said`).
    /// The client's `send` used to read an end of stream here.
    #[tokio::test]
    async fn a_handlers_error_reaches_the_client_as_a_frame() {
        let (_dir, endpoint) = a_socket();
        let server = ChannelAcceptor::<Req, Resp>::listen(endpoint.clone(), PeerUsers::OwnUser).await.expect("bind");
        let serving = tokio::spawn(async move {
            server
                .accept_with_session::<_, _, ()>(|req, _caller, _session| async move {
                    match req {
                        Req::Fail => Err(refusal()),
                        Req::Ping => Ok(Resp::Pong),
                    }
                })
                .await
        });
        let mut client = a_client(&endpoint).await;
        assert_eq!(client.send(&Req::Ping).await.expect("pong"), Resp::Pong);
        let answer = tokio::time::timeout(Duration::from_secs(5), client.send(&Req::Fail))
            .await
            .expect("the door answers")
            .expect("a frame, not an end of stream");
        assert_eq!(
            answer,
            Resp::Error {
                message: "the handler refused, in these words".into()
            }
        );
        // The connection closes after the error, as it did before the frame.
        let after = tokio::time::timeout(Duration::from_secs(5), client.send(&Req::Ping))
            .await
            .expect("bounded");
        assert!(after.is_err(), "the connection stayed open: {after:?}");
        // One connection's error does not stop the door.
        let mut next = a_client(&endpoint).await;
        assert_eq!(next.send(&Req::Ping).await.expect("a second connection"), Resp::Pong);
        serving.abort();
    }

    /// **The door's log says a handler failed and how, and not in what words.**
    /// The words went to the client in the frame; the host's log is not theirs
    /// to be kept in. One rule with the inherited loop, held on both arms
    /// (`TASK-the-two-ipc-doors-log-a-handlers-error-differently`).
    #[tokio::test]
    async fn a_handlers_error_text_reaches_the_client_and_not_the_log() {
        let capture = crate::provider::log_capture::Capture::start();
        let (_dir, endpoint) = a_socket();
        let server = ChannelAcceptor::<Req, Resp>::listen(endpoint.clone(), PeerUsers::OwnUser).await.expect("bind");
        let serving = tokio::spawn(async move {
            server
                .accept_with_session::<_, _, ()>(|_req, _caller, _session| async move {
                    Err::<Resp, _>(refusal())
                })
                .await
        });
        let mut client = a_client(&endpoint).await;
        let answer = tokio::time::timeout(Duration::from_secs(5), client.send(&Req::Fail))
            .await
            .expect("the door answers")
            .expect("a frame");
        assert_eq!(
            answer,
            Resp::Error {
                message: "the handler refused, in these words".into()
            },
            "the words reach the client",
        );
        serving.abort();

        let lines = capture.lines();
        let failed: Vec<_> = lines.iter().filter(|l| l.contains("handler failed")).collect();
        assert_eq!(failed.len(), 1, "one line for one error: {lines:?}");
        assert!(failed[0].contains("kind=Other"), "the kind is logged: {failed:?}");
        assert!(
            lines.iter().all(|l| !l.contains("in these words")),
            "the handler's words reached the log: {lines:?}"
        );
    }

    /// **The streaming door says the error, then ends the stream** — the path
    /// kvaultd's control socket and kuserd's agent socket are served through.
    #[tokio::test]
    async fn a_streaming_handlers_error_is_said_before_the_stream_ends() {
        let (_dir, endpoint) = a_socket();
        let server = ChannelAcceptor::<Req, Resp>::listen(endpoint.clone(), PeerUsers::OwnUser).await.expect("bind");
        let serving = tokio::spawn(async move {
            server
                .accept_with_session_streaming::<_, _, ()>(|req, _caller, _session| async move {
                    match req {
                        Req::Fail => Err(refusal()),
                        Req::Ping => Ok(HandlerOutput::Single(Resp::Pong)),
                    }
                })
                .await
        });
        let mut rx = a_client(&endpoint).await.send_streaming(&Req::Fail).await.expect("sent");
        let within = Duration::from_secs(5);
        let first = tokio::time::timeout(within, rx.recv()).await.expect("bounded");
        assert_eq!(
            first,
            Some(Resp::Error {
                message: "the handler refused, in these words".into()
            }),
            "the door closed the stream with nothing said"
        );
        let after = tokio::time::timeout(within, rx.recv()).await.expect("the stream ends");
        assert_eq!(after, None);
        serving.abort();
    }

    /// **A one-frame answer to a streaming request ends the stream after its
    /// frame** (#112). A `Single` leaves the connection open for a next
    /// request, so a client reading a stream waits on it with the answer in
    /// hand and nothing to end it but a guess at which frames are last;
    /// answered through [`HandlerOutput::into_stream`], its `recv` returns
    /// the frame and then `None`.
    #[tokio::test]
    async fn a_one_frame_answer_to_a_stream_ends_the_stream_after_its_frame() {
        let (_dir, endpoint) = a_socket();
        let server = ChannelAcceptor::<Req, Resp>::listen(endpoint.clone(), PeerUsers::OwnUser).await.expect("bind");
        let serving = tokio::spawn(async move {
            server
                .accept_with_session_streaming::<_, _, ()>(|req, _caller, _session| async move {
                    Ok(match req {
                        // The cause: one frame, and the door waits on.
                        Req::Fail => HandlerOutput::Single(Resp::Pong),
                        Req::Ping => HandlerOutput::Stream(HandlerOutput::Single(Resp::Pong).into_stream()),
                    })
                })
                .await
        });
        let within = Duration::from_secs(5);

        let mut rx = a_client(&endpoint).await.send_streaming(&Req::Ping).await.expect("sent");
        assert_eq!(tokio::time::timeout(within, rx.recv()).await.expect("bounded"), Some(Resp::Pong));
        let after = tokio::time::timeout(within, rx.recv()).await;
        assert_eq!(after, Ok(None), "the stream did not end after its one frame");

        // As a `Single`, the frame arrives and the stream never ends.
        let mut rx = a_client(&endpoint).await.send_streaming(&Req::Fail).await.expect("sent");
        assert_eq!(tokio::time::timeout(within, rx.recv()).await.expect("bounded"), Some(Resp::Pong));
        let after = tokio::time::timeout(Duration::from_millis(300), rx.recv()).await;
        assert!(after.is_err(), "a `Single` ended the stream after all: {after:?}");
        serving.abort();
    }

    /// A uid that is not this process's: the peer a test with one uid stands in.
    fn another_uid() -> u32 {
        crate::own_uid().wrapping_add(1)
    }

    /// **A door closes a peer of another OS user at accept, unread and unanswered**,
    /// on both accept loops. The door is told to admit only another uid, so this
    /// process, connecting over a real socket, is the peer of another user. It
    /// writes nothing and still reads the end of the stream: the door closed it
    /// without waiting for a frame, and the handler never ran.
    #[tokio::test]
    async fn a_peer_of_another_user_is_closed_at_accept_unread_and_unanswered() {
        use std::sync::atomic::{AtomicBool, Ordering};
        for streaming in [false, true] {
            let (_dir, endpoint) = a_socket();
            let server = ChannelAcceptor::<Req, Resp>::listen(endpoint.clone(), PeerUsers::Only(another_uid()))
                .await
                .expect("bind");
            let ran = Arc::new(AtomicBool::new(false));
            let seen = Arc::clone(&ran);
            let serving = tokio::spawn(async move {
                if streaming {
                    server
                        .accept_with_session_streaming::<_, _, ()>(move |_req, _caller, _session| {
                            seen.store(true, Ordering::SeqCst);
                            async move { Ok(HandlerOutput::Single(Resp::Pong)) }
                        })
                        .await
                } else {
                    server
                        .accept_with_session::<_, _, ()>(move |_req, _caller, _session| {
                            seen.store(true, Ordering::SeqCst);
                            async move { Ok(Resp::Pong) }
                        })
                        .await
                }
            });
            let mut raw = crate::OsConnection::connect(&endpoint).await.expect("connect");
            let mut buf = [0u8; 16];
            let read = tokio::time::timeout(Duration::from_secs(5), raw.read(&mut buf))
                .await
                .expect("the door closed the connection without waiting for a frame");
            assert!(matches!(read, Ok(0)), "the door said something: {read:?}");
            // A frame written now reaches nobody, and nothing answers it.
            let mut client = IpcClient::<Req, Resp, crate::OsConnection>::from_connection(raw);
            let answer = tokio::time::timeout(Duration::from_secs(5), client.send(&Req::Ping))
                .await
                .expect("bounded");
            assert!(answer.is_err(), "a refused peer was answered: {answer:?}");
            assert!(!ran.load(Ordering::SeqCst), "the handler ran for a refused peer");
            serving.abort();
        }
    }

    /// **A client refuses a server of another OS user and writes nothing.** The
    /// client is told to hold the server to another uid, so this process, serving
    /// over a real socket, is a server of another user: the connect is refused,
    /// saying nothing was sent, and the server reads the end of the stream with not
    /// one byte before it.
    #[tokio::test]
    async fn a_client_refuses_a_server_of_another_user_and_writes_nothing() {
        let (_dir, endpoint) = a_socket();
        let listener = crate::OsListener::bind(endpoint.clone()).await.expect("bind");
        let served = tokio::spawn(async move {
            let mut accepted = listener.accept_with_peer().await.expect("accept");
            let mut got = Vec::new();
            let mut buf = [0u8; 64];
            loop {
                match accepted.connection.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => got.extend_from_slice(&buf[..n]),
                }
            }
            got
        });
        let refused = IpcClient::<Req, Resp>::connect_holding(endpoint.clone(), PeerUsers::Only(another_uid()))
            .await
            .err()
            .expect("the client went on to a server of another user");
        assert_eq!(refused.kind(), io::ErrorKind::PermissionDenied);
        assert!(refused.to_string().contains("nothing was sent"), "{refused}");
        let got = tokio::time::timeout(Duration::from_secs(5), served)
            .await
            .expect("the client's connection ended")
            .expect("join");
        assert!(got.is_empty(), "the refusing client wrote {} bytes", got.len());
    }
}
