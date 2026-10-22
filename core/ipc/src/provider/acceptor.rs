// SPDX-License-Identifier: AGPL-3.0-or-later
use crate::{Caller, OsListener};
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
pub struct ChannelAcceptor<Req, Resp> {
    listener: OsListener,
    _phantom: std::marker::PhantomData<(Req, Resp)>,
}

impl<Req, Resp> ChannelAcceptor<Req, Resp>
where
    Req: for<'de> Deserialize<'de>,
    Resp: Serialize + From<io::Error>,
{
    /// Create a new IPC server listening at the given endpoint
    pub async fn listen(endpoint: IpcEndpoint) -> io::Result<Self> {
        let listener = OsListener::bind(endpoint)
            .await
            .map_err(io::Error::other)?;
        Ok(Self {
            listener,
            _phantom: std::marker::PhantomData,
        })
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
        let dir = tempfile::tempdir_in("/tmp").expect("a directory under /tmp for the socket");
        let endpoint = IpcEndpoint::UnixSocket(dir.path().join("sock"));
        (dir, endpoint)
    }

    async fn a_client(endpoint: &IpcEndpoint) -> IpcClient<Req, Resp> {
        for _ in 0..100 {
            if let Ok(c) = IpcClient::connect(endpoint.clone()).await {
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
        let server = ChannelAcceptor::<Req, Resp>::listen(endpoint.clone()).await.expect("bind");
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
        let server = ChannelAcceptor::<Req, Resp>::listen(endpoint.clone()).await.expect("bind");
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
        let server = ChannelAcceptor::<Req, Resp>::listen(endpoint.clone()).await.expect("bind");
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
}
