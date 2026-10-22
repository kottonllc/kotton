// SPDX-License-Identifier: AGPL-3.0-or-later
//! OS-specific IPC implementation
//!
//! - Unix: Unix domain sockets
//! - Windows: Named pipes

use async_trait::async_trait;
use kotton_sys::ipc::{Connection, IpcEndpoint, IpcError, Listener, IpcResult};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

// ── OS User Identity ─────────────────────────────────────────────────────────

/// The OS-level identity of the process that connected via IPC.
///
/// On Windows this is the account name returned by `GetUserNameA` after
/// impersonating the pipe client (e.g. `DOMAIN\user` or `machine\user`).
/// On Unix it is the numeric UID obtained via `SO_PEERCRED`.
/// `Unknown` is used on platforms / connection types where the credential
/// cannot be determined.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OsUserId {
    /// Windows account name, e.g. `"DESKTOP-ABC123\\alice"` or `"alice"`.
    #[cfg(windows)]
    AccountName(String),
    /// Unix numeric UID of the connecting process.
    #[cfg(unix)]
    Uid(u32),
    /// Could not determine caller identity (platform limitation or client-side
    /// connection where peer info is unavailable).
    Unknown,
}

impl std::fmt::Display for OsUserId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            #[cfg(windows)]
            OsUserId::AccountName(name) => write!(f, "{}", name),
            #[cfg(unix)]
            OsUserId::Uid(uid) => write!(f, "uid:{}", uid),
            OsUserId::Unknown => write!(f, "<unknown>"),
        }
    }
}

/// Everything the acceptor learned about who connected, from the kernel.
///
/// One type, because there was briefly nearly two. `OsUserId` answers *which
/// user* and works on both platforms; `SO_PEERCRED` also yields gid and pid,
/// which is *which process*. Those are one answer to one question and they
/// belong together — a second parallel accessor for the Unix half would be a
/// second thing to keep in step, and the first thing to fall out of step.
///
/// Nothing here is asserted by the caller. That is the entire point of it:
/// every other identity on these channels — a token, a `scope`, a header — is
/// the caller's own claim about itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Caller {
    /// Which user, in whatever form the platform expresses it.
    pub user: OsUserId,
    /// Which process. Unix only, and only where the kernel supplied it.
    ///
    /// Captured at accept, so it is not racy *for this connection*: the pid
    /// names the process that connected, even if that process later exits and
    /// the number is reused. It is still not a program identity — it says
    /// which process, never which binary — so it supports a check like "my
    /// parent" and does not generalise to "a trusted peer".
    pub pid: Option<i32>,
    /// Effective group id of the connecting process. Unix only.
    pub gid: Option<u32>,
}

impl Caller {
    /// No kernel evidence at all.
    ///
    /// Not a failure to be papered over: on a platform or transport that cannot
    /// identify its peer, this is the honest value, and an acceptor must read it
    /// as *absence of evidence* rather than as permission.
    pub fn anonymous() -> Self {
        Self {
            user: OsUserId::Unknown,
            pid: None,
            gid: None,
        }
    }
}

impl std::fmt::Display for Caller {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.pid {
            Some(pid) => write!(f, "{} pid:{}", self.user, pid),
            None => write!(f, "{}", self.user),
        }
    }
}

/// A connection accepted by the listener, bundled with what the kernel said
/// about the caller.
pub struct AcceptedConnection {
    pub connection: Box<dyn Connection>,
    pub peer: Caller,
}

#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};

#[cfg(windows)]
use std::sync::Mutex;
#[cfg(windows)]
use tokio::net::windows::named_pipe::{
    ClientOptions, NamedPipeClient, NamedPipeServer, ServerOptions,
};

#[cfg(windows)]
use std::os::windows::io::AsRawHandle;
#[cfg(windows)]
use windows_sys::Win32::{
    Foundation::HANDLE,
    Security::RevertToSelf,
    System::{Pipes::ImpersonateNamedPipeClient, WindowsProgramming::GetUserNameA},
};

#[cfg(windows)]
enum WindowsPipe {
    Client(NamedPipeClient),
    Server(NamedPipeServer),
}

// ── Windows peer credential helper ───────────────────────────────────────────

/// After a client connects to a named pipe server instance, impersonate them
/// for just long enough to call `GetUserNameA`, then revert.  Returns the
/// Windows account name (e.g. `"DESKTOP-123\\alice"`) on success.
#[cfg(windows)]
#[allow(unsafe_code)]
fn windows_pipe_peer(pipe: &NamedPipeServer) -> OsUserId {
    // SAFETY: All Win32 calls follow the documented contract.  We revert
    // immediately after reading the username, so no privileged code runs
    // under the client's token.
    unsafe {
        let handle = pipe.as_raw_handle() as HANDLE;
        if ImpersonateNamedPipeClient(handle) == 0 {
            return OsUserId::Unknown;
        }

        // 256 bytes covers all legal Windows account-name formats.
        let mut buf = [0u8; 256];
        let mut size = buf.len() as u32;
        let ok = GetUserNameA(buf.as_mut_ptr(), &mut size);

        // Always revert before returning.
        RevertToSelf();

        if ok == 0 || size == 0 {
            return OsUserId::Unknown;
        }

        // `size` includes the NUL terminator on success.
        let name_bytes = &buf[..(size as usize).saturating_sub(1)];
        match std::str::from_utf8(name_bytes) {
            Ok(s) => OsUserId::AccountName(s.to_owned()),
            Err(_) => OsUserId::Unknown,
        }
    }
}

/// A connection **opened by name** — the host's native local IPC transport.
///
/// A Unix domain socket at a path, or a Windows named pipe. That is the whole of
/// what this type is now, and it is a statement about authorisation rather than
/// about plumbing: a path is reachable, so anything running as this user can also
/// open it, and every channel built on one authenticates afterwards
/// (RFC-0082 rule 6). Its ~20 call sites all do.
///
/// **A channel you were *handed* is not this.** It is the child's own stdin and
/// stdout, handed at spawn; see `SurfaceProxy::attach`. Until
/// 2026-08-25 a `from_stream` here adopted a `socketpair` end, so this one type
/// answered "who may speak?" two different ways — possession for one caller, a
/// credential for the other twenty — and holding one told you neither. It had a
/// single caller and is deleted rather than documented.
pub struct OsConnection {
    #[cfg(unix)]
    stream: UnixStream,
    #[cfg(windows)]
    stream: WindowsPipe,
}

impl OsConnection {
    /// Open the endpoint's socket or pipe.
    #[cfg(unix)]
    pub async fn connect(endpoint: &IpcEndpoint) -> IpcResult<Self> {
        let IpcEndpoint::UnixSocket(path) = endpoint;
        let stream = UnixStream::connect(path)
            .await
            .map_err(|e| map_io_error(e, "connect"))?;

        Ok(Self { stream })
    }

    #[cfg(windows)]
    pub async fn connect(endpoint: &IpcEndpoint) -> IpcResult<Self> {
        use tokio::time::{sleep, Duration};

        let IpcEndpoint::NamedPipe(name) = endpoint;
        let pipe_path = kotton_common::paths::pipe_path(name);

        // Retry with exponential backoff when pipe is busy
        let mut retry_delay_ms = 10;
        let max_retries = 5;

        for attempt in 0..=max_retries {
            match ClientOptions::new().open(&pipe_path) {
                Ok(stream) => {
                    return Ok(Self {
                        stream: WindowsPipe::Client(stream),
                    });
                }
                Err(e) => {
                    if attempt < max_retries
                        && (e.kind() == std::io::ErrorKind::WouldBlock
                            || e.to_string().contains("pipe instances are busy"))
                    {
                        sleep(Duration::from_millis(retry_delay_ms)).await;
                        retry_delay_ms *= 2;
                        continue;
                    }
                    return Err(map_io_error(e, "connect"));
                }
            }
        }

        Err(IpcError::ConnectionFailed(format!(
            "Failed to connect after {} retries",
            max_retries
        )))
    }
}

#[async_trait]
impl Connection for OsConnection {
    async fn read(&mut self, buf: &mut [u8]) -> IpcResult<usize> {
        #[cfg(unix)]
        {
            self.stream
                .read(buf)
                .await
                .map_err(|e| map_io_error(e, "read"))
        }
        #[cfg(windows)]
        {
            match &mut self.stream {
                WindowsPipe::Client(pipe) => pipe.read(buf).await,
                WindowsPipe::Server(pipe) => pipe.read(buf).await,
            }
            .map_err(|e| map_io_error(e, "read"))
        }
    }

    async fn write(&mut self, buf: &[u8]) -> IpcResult<usize> {
        #[cfg(unix)]
        {
            self.stream
                .write(buf)
                .await
                .map_err(|e| map_io_error(e, "write"))
        }
        #[cfg(windows)]
        {
            match &mut self.stream {
                WindowsPipe::Client(pipe) => pipe.write(buf).await,
                WindowsPipe::Server(pipe) => pipe.write(buf).await,
            }
            .map_err(|e| map_io_error(e, "write"))
        }
    }

    async fn shutdown(&mut self) -> IpcResult<()> {
        #[cfg(unix)]
        {
            self.stream
                .shutdown()
                .await
                .map_err(|e| map_io_error(e, "shutdown"))
        }
        #[cfg(windows)]
        {
            // Named pipes don't have explicit shutdown
            Ok(())
        }
    }
}

/// OS IPC listener
pub struct OsListener {
    endpoint: IpcEndpoint,
    #[cfg(unix)]
    listener: UnixListener,
    /// On Windows we keep a "pending" server instance ready for the next client.
    /// Each call to accept() swaps in a fresh instance before returning the
    /// connected one, so the pipe always exists for incoming clients.
    #[cfg(windows)]
    pending: Mutex<NamedPipeServer>,
    #[cfg(windows)]
    pipe_name: String,
}

impl OsListener {
    /// Create a new IPC listener at the given endpoint
    #[cfg(unix)]
    pub async fn bind(endpoint: IpcEndpoint) -> IpcResult<Self> {
        let IpcEndpoint::UnixSocket(ref path) = endpoint;

        // Remove existing socket file if it exists
        if path.exists() {
            std::fs::remove_file(path).map_err(|e| {
                IpcError::BindFailed(format!("Failed to remove existing socket: {}", e))
            })?;
        }

        // Create parent directory with 0o700 (user-only access).
        // Using DirBuilder::mode() prevents socket squatting: the directory
        // cannot be pre-created by another process in a world-writable location.
        // mode() only applies to newly created path segments; existing dirs
        // (e.g. $XDG_RUNTIME_DIR) are left unchanged.
        if let Some(parent) = path.parent() {
            use std::os::unix::fs::DirBuilderExt;
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(parent)
                .map_err(|e| {
                    IpcError::BindFailed(format!("Failed to create socket directory: {}", e))
                })?;
        }

        let listener = UnixListener::bind(path).map_err(|e| map_io_error(e, "bind"))?;

        Ok(Self { endpoint, listener })
    }

    #[cfg(windows)]
    pub async fn bind(endpoint: IpcEndpoint) -> IpcResult<Self> {
        let IpcEndpoint::NamedPipe(ref name) = endpoint;
        let pipe_name = name.clone();
        let pipe_path = kotton_common::paths::pipe_path(&pipe_name);

        // Create the FIRST server instance so the named pipe exists immediately.
        // Clients can connect as soon as bind() returns.
        let first = ServerOptions::new()
            .first_pipe_instance(true)
            .create(&pipe_path)
            .map_err(|e| map_io_error(e, "bind"))?;

        Ok(Self {
            endpoint,
            pending: Mutex::new(first),
            pipe_name,
        })
    }
}

#[async_trait]
impl Listener for OsListener {
    #[cfg(unix)]
    async fn accept(&self) -> IpcResult<Box<dyn Connection>> {
        let (stream, _) = self
            .listener
            .accept()
            .await
            .map_err(|e| map_io_error(e, "accept"))?;

        Ok(Box::new(OsConnection { stream }))
    }

    #[cfg(windows)]
    async fn accept(&self) -> IpcResult<Box<dyn Connection>> {
        let pipe_path = kotton_common::paths::pipe_path(&self.pipe_name);

        // Prepare a fresh pending instance BEFORE we start waiting on the
        // current one.  This way the pipe always has a listening slot available
        // for the next client before we block.
        let next = ServerOptions::new()
            .first_pipe_instance(false)
            .create(&pipe_path)
            .map_err(|e| map_io_error(e, "create pipe instance"))?;

        // Atomically swap out the pending instance.
        let current = {
            let mut guard = self.pending.lock().unwrap();
            std::mem::replace(&mut *guard, next)
        };

        // Wait for a client to connect on the instance we just took ownership of.
        current
            .connect()
            .await
            .map_err(|e| map_io_error(e, "accept"))?;

        Ok(Box::new(OsConnection {
            stream: WindowsPipe::Server(current),
        }))
    }

    fn endpoint(&self) -> &IpcEndpoint {
        &self.endpoint
    }
}

impl OsListener {
    /// Like [`Listener::accept`] but also returns the OS identity of the
    /// connecting process.  On Windows this uses `ImpersonateNamedPipeClient`
    /// to read the caller's Windows account name.  On Unix it reads the
    /// peer UID via `SO_PEERCRED`.  Falls back to [`OsUserId::Unknown`] on
    /// platforms where this information is unavailable.
    pub async fn accept_with_peer(&self) -> IpcResult<AcceptedConnection> {
        #[cfg(unix)]
        {
            let (stream, _) = self
                .listener
                .accept()
                .await
                .map_err(|e| map_io_error(e, "accept"))?;

            let peer = match stream.peer_cred() {
                Ok(c) => Caller {
                    user: OsUserId::Uid(c.uid()),
                    pid: c.pid(),
                    gid: Some(c.gid()),
                },
                Err(_) => Caller::anonymous(),
            };

            Ok(AcceptedConnection {
                connection: Box::new(OsConnection { stream }),
                peer,
            })
        }

        #[cfg(windows)]
        {
            let pipe_path = kotton_common::paths::pipe_path(&self.pipe_name);

            let next = ServerOptions::new()
                .first_pipe_instance(false)
                .create(&pipe_path)
                .map_err(|e| map_io_error(e, "create pipe instance"))?;

            let current = {
                let mut guard = self.pending.lock().unwrap();
                std::mem::replace(&mut *guard, next)
            };

            current
                .connect()
                .await
                .map_err(|e| map_io_error(e, "accept"))?;

            // Capture peer identity while we still hold the raw handle.
            // Win32 can supply a client process id via GetNamedPipeClientProcessId;
            // it is not wired up, so pid stays None rather than being invented.
            let peer = Caller {
                user: windows_pipe_peer(&current),
                pid: None,
                gid: None,
            };

            Ok(AcceptedConnection {
                connection: Box::new(OsConnection {
                    stream: WindowsPipe::Server(current),
                }),
                peer,
            })
        }
    }
}

/// Map std::io::Error to IpcError
pub(crate) fn map_io_error(error: std::io::Error, context: &str) -> IpcError {
    match error.kind() {
        std::io::ErrorKind::NotFound => IpcError::NotFound(context.to_string()),
        std::io::ErrorKind::PermissionDenied => IpcError::PermissionDenied(context.to_string()),
        std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::ConnectionReset => {
            IpcError::ConnectionFailed(format!("{}: {}", context, error))
        }
        _ => IpcError::IoError(format!("{}: {}", context, error)),
    }
}

#[cfg(test)]
mod tests {
    // The only test here is Unix-only, so the glob is too — importing it
    // unconditionally warns on Windows.
    #[cfg(unix)]
    use super::*;

    /// The acceptor learns who connected, over a real socket.
    ///
    /// Uses `OsListener::accept_with_peer`, not the in-memory transport:
    /// the claim is that a `Caller` comes back populated, and the memory
    /// provider has no kernel to ask, so a test written against it would pass
    /// while proving the opposite.
    ///
    /// It asserts our own pid and uid because those are the only values this
    /// process can know independently — which is also the honest limit of what
    /// a single-process test can show.
    #[cfg(unix)]
    #[tokio::test]
    async fn the_acceptor_learns_who_connected() {
        // Under `/tmp`, not joined onto `TMPDIR`, whose length no test sets; and
        // removed when `tmp` drops, pass or panic (TASK-three-unit-tests-join-their-socket-onto-tmpdir-by-hand).
        let tmp = tempfile::tempdir_in("/tmp").expect("a directory under /tmp for the socket");
        let dir = tmp.path();
        let path = dir.join("sock");
        let endpoint = IpcEndpoint::UnixSocket(path.clone());

        let listener = OsListener::bind(endpoint.clone()).await.expect("bind");
        let accept = tokio::spawn(async move { listener.accept_with_peer().await });

        let _client = OsConnection::connect(&endpoint).await.expect("connect");
        let accepted = accept.await.expect("join").expect("accept");

        // pid is the assertion that matters: it is the evidence socket
        // permissions cannot give, and it is exact.
        assert_eq!(
            accepted.peer.pid,
            Some(std::process::id() as i32),
            "the connecting process is this test process",
        );

        // uid, without `libc` — the workspace denies `unsafe`, and a file we
        // just created carries our own euid.
        use std::os::unix::fs::MetadataExt;
        let probe = dir.join("uid-probe");
        std::fs::write(&probe, b"").expect("write probe");
        let ours = std::fs::metadata(&probe).expect("stat probe").uid();
        assert_eq!(accepted.peer.user, OsUserId::Uid(ours), "uid should be ours");
        assert_eq!(accepted.peer.gid, Some(ours), "gid is supplied too");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_unix_socket_connection() {
        // As above: a directory this test makes under `/tmp` and drops (TASK-three-unit-tests-join-their-socket-onto-tmpdir-by-hand).
        let tmp = tempfile::tempdir_in("/tmp").expect("a directory under /tmp for the socket");
        let endpoint = IpcEndpoint::UnixSocket(tmp.path().join("sock"));

        // Create listener
        let listener = OsListener::bind(endpoint.clone()).await.unwrap();

        // Connect in background
        let endpoint_clone = endpoint.clone();
        let handle =
            tokio::spawn(async move { OsConnection::connect(&endpoint_clone).await.unwrap() });

        // Accept connection
        let mut server_conn = listener.accept().await.unwrap();
        let mut client_conn = handle.await.unwrap();

        // Test write/read
        let msg = b"hello";
        client_conn.write(msg).await.unwrap();

        let mut buf = [0u8; 5];
        let n = server_conn.read(&mut buf).await.unwrap();
        assert_eq!(n, 5);
        assert_eq!(&buf, msg);
    }
}
