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

    /// **The kernel names this peer as this process's own effective uid**
    /// ([`own_uid`]), or the peer is refused: any other uid, and a peer the kernel
    /// did not name ([`OsUserId::Unknown`]), which is never read as permission.
    ///
    /// The one check for both ends of a door that serves only its own user
    /// ([`PeerUsers::OwnUser`]): kdeviced's and kuserd's acceptors hold each
    /// connection to it at accept, and `IpcClient::connect_to_own_user` holds the
    /// server it reached to it before sending (`kotton_wire::sys_ipc`).
    #[cfg(unix)]
    pub fn require_own_user(&self) -> std::io::Result<()> {
        let me = own_uid();
        if self.user == OsUserId::Uid(me) {
            return Ok(());
        }
        let who = match self.user {
            OsUserId::Unknown => format!("a peer the kernel does not name ({self})"),
            _ => format!("{self}"),
        };
        Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("{who} is not uid {me}, the user this process runs as"),
        ))
    }
}

/// **Which OS users one end of a door holds the other end to**, by the kernel's
/// answer for its peer ([`Caller`]). An acceptor holds each connection to it at
/// accept, before a frame is read, and closes one it refuses with no reply
/// ([`crate::ChannelAcceptor::listen`]); a client holds the server it reached to it
/// before it writes a frame ([`OsConnection::connect_holding`]). A peer the
/// kernel does not name ([`OsUserId::Unknown`]) is never one of them.
///
/// Unix only in effect: on Windows the pipe's peer is not held to it here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerUsers {
    /// This process's own effective uid ([`own_uid`]) and no other: kdeviced's and
    /// kuserd's doors, and every client of them (`kotton_wire::sys_ipc`).
    OwnUser,
    /// This process's own effective uid, or root: kvaultd's door, which the host's
    /// shell reaches as root or as the vault's own user.
    OwnUserOrRoot,
    /// Exactly this uid: how a test with one uid stands in a peer of another.
    #[cfg(test)]
    Only(u32),
}

impl PeerUsers {
    /// `peer` is one of these users, or the refusal says who it was and who is
    /// answered; its kind is [`std::io::ErrorKind::PermissionDenied`].
    #[cfg(unix)]
    pub fn require(self, peer: &Caller) -> std::io::Result<()> {
        let me = own_uid();
        let (admitted, wanted) = match self {
            Self::OwnUser => return peer.require_own_user(),
            Self::OwnUserOrRoot => (
                peer.user == OsUserId::Uid(me) || peer.user == OsUserId::Uid(0),
                format!("uid {me}, the user this process runs as, nor root"),
            ),
            #[cfg(test)]
            Self::Only(uid) => (peer.user == OsUserId::Uid(uid), format!("uid {uid}")),
        };
        if admitted {
            return Ok(());
        }
        let who = match peer.user {
            OsUserId::Unknown => format!("a peer the kernel does not name ({peer})"),
            _ => format!("{peer}"),
        };
        Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("{who} is not {wanted}"),
        ))
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

/// The effective uid this process runs as: the uid a socket's directory must be owned
/// by ([`OsListener::bind`]), and the uid a client requires of the process serving the
/// socket it reached (`IpcClient::connect_to_own_user`).
#[cfg(unix)]
pub fn own_uid() -> u32 {
    rustix::process::geteuid().as_raw()
}

/// What the kernel says about the process at the other end of `stream`
/// (`SO_PEERCRED`), on either end of the connection. [`Caller::anonymous`] when the
/// kernel gave no answer, which no check reads as permission.
#[cfg(unix)]
fn unix_peer(stream: &UnixStream) -> Caller {
    match stream.peer_cred() {
        Ok(c) => Caller {
            user: OsUserId::Uid(c.uid()),
            pid: c.pid(),
            gid: Some(c.gid()),
        },
        Err(_) => Caller::anonymous(),
    }
}

/// The one clause every refusal of a socket's directory ends with: the variables
/// that move a daemon's door (`kotton_common::paths::runtime_dir`'s tiers), which the
/// daemon and its clients must be given alike.
#[cfg(target_os = "linux")]
const SOCKET_DIR_WAY_OUT: &str = "a daemon and its clients move their sockets together \
     when started with the same XDG_RUNTIME_DIR (or, with that unset, the same TMPDIR) \
     naming a directory of this user's own";
#[cfg(all(unix, not(target_os = "linux")))]
const SOCKET_DIR_WAY_OUT: &str = "a daemon and its clients move their sockets together \
     when started with the same TMPDIR naming a directory of this user's own";

/// A refusal of the socket directory `dir` at the bind: the path, what is wrong
/// (`why`), the rule and the way out, in one message.
#[cfg(unix)]
fn refuse_socket_dir(dir: &std::path::Path, why: &str) -> IpcError {
    IpcError::BindFailed(format!(
        "the socket directory {} {why}; a socket is bound only in a directory, not a \
         symlink, owned by uid {} and granting group and other no permission bits; \
         {SOCKET_DIR_WAY_OUT}",
        dir.display(),
        own_uid()
    ))
}

/// **A socket's directory is its owner's alone**: its own entry (a symlink there is
/// not followed) is a directory, owned by `owner`, granting group and other nothing
/// (`mode & 0o077 == 0`). `Err` says what is wrong with it, for the caller to name
/// the path in its own refusal.
///
/// The one predicate for a door's directory, at both ends. The bind holds the
/// directory it binds in to it for its own uid ([`own_uid`]), whether it just made
/// it `0o700` or found it there, whatever tier of `kotton_common::paths::runtime_dir`
/// or its short `/tmp` fallback chose it, and changes nothing when it does not hold.
/// A root client holds the directory of the door it reached to it for the uid it
/// read from that same entry ([`door_dir_owner`]).
#[cfg(unix)]
fn check_socket_dir(dir: &std::path::Path, owner: u32) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt as _;
    let entry = match std::fs::symlink_metadata(kotton_common::fs::own_entry(dir)) {
        Ok(entry) => entry,
        Err(e) => return Err(format!("cannot be read ({e})")),
    };
    if entry.file_type().is_symlink() {
        return Err("is a symlink".into());
    }
    if !entry.is_dir() {
        return Err("is not a directory".into());
    }
    if entry.uid() != owner {
        return Err(format!("is owned by uid {}", entry.uid()));
    }
    let mode = entry.mode() & 0o7777;
    if mode & 0o077 != 0 {
        return Err(format!("is open to other users (mode {mode:04o})"));
    }
    Ok(())
}

/// **Every directory above `path`, up to `/`, is root's or `owner`'s, and no one
/// else may write it**: each ancestor's own entry (a symlink is not followed) is a
/// directory, owned by root or by `owner`, granting group and other no write
/// (`mode & 0o022 == 0`; a sticky bit does not stand in for it, so `/tmp` does not
/// hold). Then only those two users can change what `path` names. `path` itself is
/// not read here: its caller holds it to its own rule.
///
/// `path` is absolute and has no `.` or `..` in it, or it is refused: the walk is of
/// the entries the kernel resolves, from `/`. A refusal names the entry that does
/// not hold and what is wrong with it, and its kind is
/// [`std::io::ErrorKind::PermissionDenied`].
///
/// What a root client holds the ancestors of a door's directory to
/// ([`door_dir_owner`]), and what a root `kvaultd` verb holds the ancestors of the
/// settings file it takes a door's path from to, with `owner` root.
#[cfg(unix)]
pub fn check_ancestors(path: &std::path::Path, owner: u32) -> std::io::Result<()> {
    use std::os::unix::fs::MetadataExt as _;
    use std::path::Component;
    let whose = if owner == 0 { "root".to_string() } else { format!("root or uid {owner}") };
    let refuse = |entry: &std::path::Path, why: String| {
        Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "{} {why}; every directory above it, up to /, must be a directory, not a \
                 symlink, owned by {whose} and granting group and other no write",
                entry.display()
            ),
        ))
    };
    if !path.is_absolute() || !path.components().all(|c| matches!(c, Component::RootDir | Component::Normal(_))) {
        return refuse(path, "is not an absolute path free of `.` and `..`".into());
    }
    let path = kotton_common::fs::own_entry(path);
    for above in path.ancestors().skip(1) {
        let entry = match std::fs::symlink_metadata(above) {
            Ok(entry) => entry,
            Err(e) => return refuse(above, format!("cannot be read ({e})")),
        };
        if entry.file_type().is_symlink() {
            return refuse(above, "is a symlink".into());
        }
        if !entry.is_dir() {
            return refuse(above, "is not a directory".into());
        }
        if entry.uid() != 0 && entry.uid() != owner {
            return refuse(above, format!("is owned by uid {}", entry.uid()));
        }
        let mode = entry.mode() & 0o7777;
        if mode & 0o022 != 0 {
            return refuse(above, format!("is writable by other users (mode {mode:04o})"));
        }
    }
    Ok(())
}

/// **The uid that owns the directory `door` is in**, once that directory holds
/// [`check_socket_dir`] for the uid read from its own entry and every ancestor holds
/// [`check_ancestors`] for it. Under both, only root and that uid can change what
/// `door` names. A refusal names the entry that does not hold, and its kind is
/// [`std::io::ErrorKind::PermissionDenied`].
#[cfg(unix)]
fn door_dir_owner(door: &std::path::Path) -> std::io::Result<u32> {
    use std::os::unix::fs::MetadataExt as _;
    let dir = door.parent().unwrap_or(door);
    let refuse = |why: String| {
        std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "the door's directory {} {why}; a root client speaks only at a door whose \
                 directory is not a symlink, is owned by one uid and grants group and other \
                 no permission bits",
                dir.display()
            ),
        )
    };
    let owner = std::fs::symlink_metadata(kotton_common::fs::own_entry(dir))
        .map_err(|e| refuse(format!("cannot be read ({e})")))?
        .uid();
    check_socket_dir(dir, owner).map_err(refuse)?;
    check_ancestors(dir, owner)?;
    Ok(owner)
}

/// **A root client speaks only to root, or to the uid that owns the door's
/// directory** (kottonllc/kotton#527): `peer` is the server the kernel names for the
/// connection to `door`, and `root` the uid that counts as root here (`0`; a test
/// stands another in, as `PeerUsers::Only` stands in a peer).
///
/// A server that is root is held as [`PeerUsers::OwnUser`] holds it for a root
/// client, and no directory is read. Any other server is answered only when the
/// door's directory and its ancestors hold ([`door_dir_owner`]) and the kernel names
/// the server as the uid that owns that directory. A door in the short `/tmp`
/// fallback does not hold, and is reached by its own user.
#[cfg(unix)]
fn hold_door_server(peer: &Caller, door: &std::path::Path, root: u32) -> std::io::Result<()> {
    if peer.user == OsUserId::Uid(root) {
        return Ok(());
    }
    let owner = door_dir_owner(door)?;
    if peer.user == OsUserId::Uid(owner) {
        return Ok(());
    }
    let who = match peer.user {
        OsUserId::Unknown => format!("a peer the kernel does not name ({peer})"),
        _ => format!("{peer}"),
    };
    Err(std::io::Error::new(
        std::io::ErrorKind::PermissionDenied,
        format!(
            "{who} is not root, nor uid {owner}, which owns the door's directory {}",
            door.parent().unwrap_or(door).display()
        ),
    ))
}

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

    /// Open the endpoint, and go no further unless its server is one of `users`.
    ///
    /// On Unix the kernel's answer for the peer of the connected stream
    /// ([`Self::peer`]) is held to [`PeerUsers::require`]; any other uid, or no
    /// answer, is refused and the connection dropped before a byte is written, so
    /// nothing a client would sign or say — a token, a PIN, a phrase, a code —
    /// reaches a process of another user.
    ///
    /// On Windows it is [`Self::connect`]: the pipe's server is not identified here.
    #[cfg_attr(not(unix), allow(unused_variables))]
    pub async fn connect_holding(endpoint: &IpcEndpoint, users: PeerUsers) -> std::io::Result<Self> {
        let connection = Self::connect(endpoint).await.map_err(std::io::Error::other)?;
        #[cfg(unix)]
        users.require(&connection.peer()).map_err(|e| {
            let IpcEndpoint::UnixSocket(path) = endpoint;
            std::io::Error::new(
                e.kind(),
                format!("the server at {}: {e}; nothing was sent to it", path.display()),
            )
        })?;
        Ok(connection)
    }

    /// Open the door at `endpoint` as a root client does, and go no further unless
    /// its server is root, or is the uid that owns the door's directory once that
    /// directory and every ancestor up to `/` hold one predicate
    /// ([`check_socket_dir`] for that uid, then [`check_ancestors`]).
    ///
    /// For a root client of a door served by a user of its own (kvaultd's): from
    /// root's side [`PeerUsers::OwnUser`] names root, so the user the door is held to
    /// is the one the host's filesystem names, read by number. A door root serves is
    /// held as `OwnUser` holds it, with no directory read. A door whose path does not
    /// hold, the short `/tmp` fallback's among them, is refused naming the entry,
    /// and so is a server of any other user: the connection is dropped before a byte
    /// is written.
    #[cfg(unix)]
    pub async fn connect_holding_root_or_door_owner(endpoint: &IpcEndpoint) -> std::io::Result<Self> {
        Self::connect_holding_door(endpoint, 0).await
    }

    /// [`Self::connect_holding_root_or_door_owner`], with `root` the uid that counts
    /// as root: `0`, or another a test stands in.
    #[cfg(unix)]
    async fn connect_holding_door(endpoint: &IpcEndpoint, root: u32) -> std::io::Result<Self> {
        let connection = Self::connect(endpoint).await.map_err(std::io::Error::other)?;
        let IpcEndpoint::UnixSocket(path) = endpoint;
        hold_door_server(&connection.peer(), path, root).map_err(|e| {
            std::io::Error::new(
                e.kind(),
                format!("the server at {}: {e}; nothing was sent to it", path.display()),
            )
        })?;
        Ok(connection)
    }

    /// Who serves this connection, as the kernel says: the uid, gid and pid of the
    /// process that accepted it.
    #[cfg(unix)]
    pub fn peer(&self) -> Caller {
        unix_peer(&self.stream)
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

        // The socket's directory. Its own entry is read first (a symlink there is not
        // followed): only when nothing is there is it made, 0o700 (`mode` applies to
        // the segments this creates and to none that exist). Whatever is there —
        // made here or found, a directory, a symlink, dangling or not, or a file — is
        // then held to `check_socket_dir`, so each refusal names the path and what is
        // wrong with it. Only then is a stale socket in it removed and the new one
        // bound.
        let parent = match path.parent() {
            Some(p) if !p.as_os_str().is_empty() => p,
            _ => std::path::Path::new("."),
        };
        let there = std::fs::symlink_metadata(kotton_common::fs::own_entry(parent));
        if matches!(&there, Err(e) if e.kind() == std::io::ErrorKind::NotFound) {
            use std::os::unix::fs::DirBuilderExt;
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(parent)
                .map_err(|e| refuse_socket_dir(parent, &format!("cannot be made ({e})")))?;
        }
        check_socket_dir(parent, own_uid()).map_err(|why| refuse_socket_dir(parent, &why))?;

        // Remove existing socket file if it exists
        if path.exists() {
            std::fs::remove_file(path).map_err(|e| {
                IpcError::BindFailed(format!("Failed to remove existing socket: {}", e))
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

            let peer = unix_peer(&stream);

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
pub(crate) mod tests {
    // The tests here are Unix-only, so the glob is too — importing it
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
        let tmp = socket_dir();
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
        let tmp = socket_dir();
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

    /// **A client learns who serves its connection**: the peer of the stream it
    /// opened is this process, the one that bound and accepted, and its uid is
    /// [`own_uid`].
    #[cfg(unix)]
    #[tokio::test]
    async fn a_client_learns_who_serves_it() {
        let tmp = socket_dir();
        let endpoint = IpcEndpoint::UnixSocket(tmp.path().join("sock"));
        let listener = OsListener::bind(endpoint.clone()).await.expect("bind");
        let accept = tokio::spawn(async move { listener.accept_with_peer().await });
        let client = OsConnection::connect(&endpoint).await.expect("connect");
        let _accepted = accept.await.expect("join").expect("accept");
        let server = client.peer();
        assert_eq!(server.user, OsUserId::Uid(own_uid()));
        assert_eq!(server.pid, Some(std::process::id() as i32));
    }

    /// A directory under `/tmp` for a test's socket, made `0700` at `mkdir` as the
    /// bind requires of the directory it binds in; removed when it drops.
    #[cfg(unix)]
    pub(crate) fn socket_dir() -> tempfile::TempDir {
        use std::os::unix::fs::PermissionsExt as _;
        tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir_in("/tmp")
            .expect("a directory under /tmp for the socket")
    }

    #[cfg(unix)]
    fn mode_of(p: &std::path::Path) -> u32 {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::symlink_metadata(p).unwrap().permissions().mode() & 0o7777
    }

    #[cfg(unix)]
    fn bind_refusal(endpoint: IpcEndpoint) -> String {
        let runtime = tokio::runtime::Builder::new_current_thread().build().unwrap();
        match runtime.block_on(OsListener::bind(endpoint)) {
            Ok(_) => panic!("the bind was not refused"),
            Err(e) => e.to_string(),
        }
    }

    /// **A missing socket directory is made `0700`**, its missing parents too, and
    /// the socket is bound in it.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_fresh_socket_directory_is_made_owner_only() {
        let tmp = tempfile::tempdir_in("/tmp").expect("scratch");
        let dir = tmp.path().join("run").join("kotton");
        let path = dir.join("sock");
        let endpoint = IpcEndpoint::UnixSocket(path.clone());
        let _listener = OsListener::bind(endpoint).await.expect("bind");
        assert_eq!(mode_of(&dir), 0o700);
        assert_eq!(mode_of(&tmp.path().join("run")), 0o700);
        assert!(path.exists(), "the socket is bound");
    }

    /// **An existing socket directory open to other users is refused** — `0755`
    /// here — with its path and mode named, its mode left as it was, and no socket
    /// bound or removed in it.
    #[cfg(unix)]
    #[test]
    fn an_existing_socket_directory_open_to_others_is_refused() {
        use std::os::unix::fs::PermissionsExt as _;
        let tmp = tempfile::tempdir_in("/tmp").expect("scratch");
        let dir = tmp.path().join("kotton");
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let stale = dir.join("sock");
        std::fs::write(&stale, b"").unwrap();
        let refusal = bind_refusal(IpcEndpoint::UnixSocket(stale.clone()));
        assert!(refusal.contains(&dir.display().to_string()), "{refusal}");
        assert!(refusal.contains("mode 0755"), "{refusal}");
        assert_eq!(mode_of(&dir), 0o755, "the directory's mode was changed");
        assert!(stale.exists(), "a file in a directory that is not ours was removed");
    }

    /// **A socket directory that is a symlink is refused**, even to a directory
    /// that is itself `0700` and ours.
    #[cfg(unix)]
    #[test]
    fn a_socket_directory_that_is_a_symlink_is_refused() {
        use std::os::unix::fs::PermissionsExt as _;
        let tmp = tempfile::tempdir_in("/tmp").expect("scratch");
        let real = tmp.path().join("real");
        std::fs::create_dir(&real).unwrap();
        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o700)).unwrap();
        let link = tmp.path().join("kotton");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let refusal = bind_refusal(IpcEndpoint::UnixSocket(link.join("sock")));
        assert!(refusal.contains("is a symlink"), "{refusal}");
        assert!(refusal.contains(&link.display().to_string()), "{refusal}");
        assert!(!real.join("sock").exists(), "a socket was bound through the symlink");
    }

    /// Every refusal of a socket's directory names the rule and the way out.
    #[cfg(unix)]
    fn says_the_rule_and_the_way_out(refusal: &str) {
        assert!(refusal.contains("granting group and other no permission bits"), "{refusal}");
        assert!(refusal.contains("TMPDIR"), "{refusal}");
        #[cfg(target_os = "linux")]
        assert!(refusal.contains("XDG_RUNTIME_DIR"), "{refusal}");
    }

    /// **A dangling symlink at the directory's name is refused as a symlink**,
    /// naming the path, and nothing is made where it points.
    #[cfg(unix)]
    #[test]
    fn a_dangling_symlink_at_the_socket_directory_is_refused_by_name() {
        let tmp = tempfile::tempdir_in("/tmp").expect("scratch");
        let nowhere = tmp.path().join("nowhere");
        let link = tmp.path().join("kotton");
        std::os::unix::fs::symlink(&nowhere, &link).unwrap();
        let refusal = bind_refusal(IpcEndpoint::UnixSocket(link.join("sock")));
        assert!(refusal.contains(&link.display().to_string()), "{refusal}");
        assert!(refusal.contains("is a symlink"), "{refusal}");
        says_the_rule_and_the_way_out(&refusal);
        assert!(!nowhere.exists(), "the bind made the symlink's target");
    }

    /// **A regular file at the directory's name is refused as not a directory**,
    /// naming the path, and the file is left as it was.
    #[cfg(unix)]
    #[test]
    fn a_file_at_the_socket_directory_is_refused_by_name() {
        let tmp = tempfile::tempdir_in("/tmp").expect("scratch");
        let file = tmp.path().join("kotton");
        std::fs::write(&file, b"kept").unwrap();
        let refusal = bind_refusal(IpcEndpoint::UnixSocket(file.join("sock")));
        assert!(refusal.contains(&file.display().to_string()), "{refusal}");
        assert!(refusal.contains("is not a directory"), "{refusal}");
        says_the_rule_and_the_way_out(&refusal);
        assert_eq!(std::fs::read(&file).unwrap(), b"kept");
    }

    /// **A directory the bind cannot make is refused by name**, with why it could
    /// not be made. Its parent is one this process cannot write: a `0500`
    /// directory of its own, or, for root, which writes past mode bits, `/proc`.
    #[cfg(unix)]
    #[test]
    fn a_socket_directory_that_cannot_be_made_is_refused_by_name() {
        use std::os::unix::fs::PermissionsExt as _;
        let tmp = tempfile::tempdir_in("/tmp").expect("scratch");
        let dir = if own_uid() != 0 {
            let locked = tmp.path().join("locked");
            std::fs::create_dir(&locked).unwrap();
            std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o500)).unwrap();
            locked.join("kotton")
        } else if cfg!(target_os = "linux") {
            std::path::PathBuf::from(format!("/proc/kotton-{}", std::process::id()))
        } else {
            eprintln!("root writes any directory here; this shape is not exercised");
            return;
        };
        let refusal = bind_refusal(IpcEndpoint::UnixSocket(dir.join("sock")));
        assert!(refusal.contains(&dir.display().to_string()), "{refusal}");
        assert!(refusal.contains("cannot be made"), "{refusal}");
        says_the_rule_and_the_way_out(&refusal);
        assert!(!dir.exists());
    }

    /// **A peer is answered only as this process's own uid**: another uid and a peer
    /// the kernel does not name are refused, each saying who it was — the check both
    /// kdeviced and `IpcClient::connect_to_own_user` hold their peer to.
    #[cfg(unix)]
    #[test]
    fn only_the_own_uid_is_answered_as_the_own_user() {
        let me = own_uid();
        let at = |user| Caller { user, pid: Some(7), gid: None };
        assert!(at(OsUserId::Uid(me)).require_own_user().is_ok());

        let another = at(OsUserId::Uid(me.wrapping_add(1))).require_own_user().unwrap_err();
        assert_eq!(another.kind(), std::io::ErrorKind::PermissionDenied);
        let said = another.to_string();
        assert!(said.contains(&format!("uid:{}", me.wrapping_add(1))), "{said}");
        assert!(said.contains(&format!("is not uid {me}")), "{said}");

        let unnamed = Caller::anonymous().require_own_user().unwrap_err();
        assert_eq!(unnamed.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(unnamed.to_string().contains("the kernel does not name"), "{unnamed}");
    }

    /// **kvaultd's door admits its own uid and root, and no other**: another uid
    /// and a peer the kernel does not name are refused, each saying who it was and
    /// who is admitted. `OwnUser` is [`Caller::require_own_user`] exactly.
    #[cfg(unix)]
    #[test]
    fn own_user_or_root_admits_those_two_and_no_other() {
        let me = own_uid();
        let at = |uid| Caller { user: OsUserId::Uid(uid), pid: Some(7), gid: None };
        // A uid that is neither this one nor root.
        let other = (1..=2).map(|d| me.wrapping_add(d)).find(|u| *u != 0).unwrap();

        assert!(PeerUsers::OwnUserOrRoot.require(&at(me)).is_ok());
        assert!(PeerUsers::OwnUserOrRoot.require(&at(0)).is_ok());
        let refused = PeerUsers::OwnUserOrRoot.require(&at(other)).unwrap_err();
        assert_eq!(refused.kind(), std::io::ErrorKind::PermissionDenied);
        let said = refused.to_string();
        assert!(said.contains(&format!("uid:{other}")), "{said}");
        assert!(said.contains(&format!("is not uid {me}")) && said.contains("nor root"), "{said}");
        let unnamed = PeerUsers::OwnUserOrRoot.require(&Caller::anonymous()).unwrap_err();
        assert!(unnamed.to_string().contains("the kernel does not name"), "{unnamed}");

        assert!(PeerUsers::OwnUser.require(&at(me)).is_ok());
        assert!(PeerUsers::OwnUser.require(&at(other)).is_err());
        assert!(PeerUsers::OwnUser.require(&Caller::anonymous()).is_err());
        if me != 0 {
            assert!(PeerUsers::OwnUser.require(&at(0)).is_err(), "root is not this user");
        }
    }

    /// A uid that is neither this process's nor root's.
    #[cfg(unix)]
    fn another_uid() -> u32 {
        (1..=2).map(|d| own_uid().wrapping_add(d)).find(|u| *u != 0).unwrap()
    }

    /// A directory whose ancestors, up to `/`, hold [`check_ancestors`] for this
    /// process's uid: under the directory this test binary was built into, which a
    /// checkout's build leaves owned by its user and closed to others' writes, not
    /// under `/tmp`, which is open to everyone's. `0700`, removed when it drops.
    #[cfg(unix)]
    fn held_dir() -> tempfile::TempDir {
        use std::os::unix::fs::PermissionsExt as _;
        let exe = std::env::current_exe().expect("this test's binary");
        let base = exe.parent().expect("its directory");
        check_ancestors(&base.join("x"), own_uid())
            .unwrap_or_else(|e| panic!("this checkout's build directory does not hold, so nothing here can: {e}"));
        tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir_in(base)
            .expect("a directory beside this test's binary")
    }

    /// **Each ancestor of a door's directory is held, up to `/`, and a refusal names
    /// the entry**: one group- or other-writable (`/tmp`, sticky bit and all, and a
    /// `0775` directory of this user's), a symlink, and a relative path are each
    /// refused by name; a clean path holds.
    #[cfg(unix)]
    #[test]
    fn every_ancestor_of_a_door_is_held_and_a_refusal_names_the_entry() {
        use std::os::unix::fs::PermissionsExt as _;
        let me = own_uid();
        let base = held_dir();
        let dir = base.path().join("a").join("kotton");
        std::fs::create_dir_all(&dir).unwrap();
        check_ancestors(&dir, me).expect("a clean path holds");

        let open = base.path().join("a");
        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o775)).unwrap();
        let refused = check_ancestors(&dir, me).unwrap_err();
        assert_eq!(refused.kind(), std::io::ErrorKind::PermissionDenied);
        let said = refused.to_string();
        assert!(said.starts_with(&format!("{} is writable by other users (mode 0775)", open.display())), "{said}");
        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o755)).unwrap();

        let real = base.path().join("real");
        std::fs::create_dir_all(real.join("kotton")).unwrap();
        let link = base.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let said = check_ancestors(&link.join("kotton"), me).unwrap_err().to_string();
        assert!(said.starts_with(&format!("{} is a symlink", link.display())), "{said}");

        let tmp = socket_dir();
        let said = check_ancestors(&tmp.path().join("kotton"), me).unwrap_err().to_string();
        assert!(said.starts_with("/tmp is writable by other users (mode 1777)"), "{said}");

        let said = check_ancestors(std::path::Path::new("run/kotton"), me).unwrap_err().to_string();
        assert!(said.contains("is not an absolute path"), "{said}");
        let dotted = base.path().join("a").join("..").join("a").join("kotton");
        let said = check_ancestors(&dotted, me).unwrap_err().to_string();
        assert!(said.contains("is not an absolute path free of `.` and `..`"), "{said}");
    }

    /// **An ancestor owned by a third uid is refused by name**; one owned by the
    /// directory's owner holds. Root only: no other user can give a directory away.
    #[cfg(unix)]
    #[test]
    fn an_ancestor_another_user_owns_is_refused_by_name() {
        if own_uid() != 0 {
            eprintln!("skipped: only root can make a directory owned by another uid");
            return;
        }
        let base = held_dir();
        let theirs = base.path().join("theirs");
        let dir = theirs.join("kotton");
        std::fs::create_dir_all(&dir).unwrap();
        let (owner, third) = (another_uid(), another_uid().wrapping_add(7));
        std::os::unix::fs::chown(&theirs, Some(owner), None).unwrap();
        check_ancestors(&dir, owner).expect("an ancestor the directory's owner owns holds");
        std::os::unix::fs::chown(&theirs, Some(third), None).unwrap();
        let said = check_ancestors(&dir, owner).unwrap_err().to_string();
        assert!(said.starts_with(&format!("{} is owned by uid {third}", theirs.display())), "{said}");
        assert!(said.contains(&format!("owned by root or uid {owner}")), "{said}");
    }

    /// **A root client answers root, or the door directory's owner, and no other**:
    /// held to the kernel's answer for the server and the uid the directory's own
    /// entry names, after the directory holds [`check_socket_dir`] for that uid.
    #[cfg(unix)]
    #[test]
    fn a_root_client_answers_root_or_the_door_directorys_owner_and_no_other() {
        use std::os::unix::fs::PermissionsExt as _;
        let me = own_uid();
        let at = |uid| Caller { user: OsUserId::Uid(uid), pid: Some(7), gid: None };
        let root = another_uid();
        let base = held_dir();
        let dir = base.path().join("kotton");
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let door = dir.join("vault.sock");

        // Root is answered with no directory read: a door nowhere is no refusal.
        hold_door_server(&at(root), std::path::Path::new("/nowhere/at/all/vault.sock"), root).expect("root");
        // The directory's owner is answered.
        hold_door_server(&at(me), &door, root).expect("the directory's owner");
        // A third uid, and a server the kernel does not name, are not.
        let third = root.wrapping_add(1);
        let said = hold_door_server(&at(third), &door, root).unwrap_err().to_string();
        assert!(said.contains(&format!("uid:{third} pid:7 is not root, nor uid {me}")), "{said}");
        let said = hold_door_server(&Caller::anonymous(), &door, root).unwrap_err().to_string();
        assert!(said.contains("the kernel does not name"), "{said}");
        // The owner too, once the directory is open to others: the one predicate.
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o750)).unwrap();
        let refused = hold_door_server(&at(me), &door, root).unwrap_err();
        assert_eq!(refused.kind(), std::io::ErrorKind::PermissionDenied);
        let said = refused.to_string();
        assert!(said.contains(&format!("the door's directory {} is open to other users (mode 0750)", dir.display())), "{said}");
    }

    /// The bytes a server at `endpoint` reads from its first connection, to its end.
    #[cfg(unix)]
    fn bytes_read_at(listener: OsListener) -> tokio::task::JoinHandle<Vec<u8>> {
        tokio::spawn(async move {
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
        })
    }

    /// **A refusing root client writes nothing**, over a real socket. Root is stood
    /// in by another uid, so this process, serving, is not root; its door is in a
    /// directory under `/tmp`, whose ancestors do not hold. The connect is refused
    /// naming `/tmp` and saying nothing was sent, and the server reads the end of
    /// the stream with not one byte before it.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_root_client_refusing_a_door_writes_nothing() {
        let tmp = socket_dir();
        let endpoint = IpcEndpoint::UnixSocket(tmp.path().join("vault.sock"));
        let served = bytes_read_at(OsListener::bind(endpoint.clone()).await.expect("bind"));
        let refused = OsConnection::connect_holding_door(&endpoint, another_uid())
            .await
            .err()
            .expect("the root client went on at a door whose path does not hold");
        assert_eq!(refused.kind(), std::io::ErrorKind::PermissionDenied);
        let said = refused.to_string();
        assert!(said.contains("/tmp is writable by other users"), "{said}");
        assert!(said.contains("nothing was sent"), "{said}");
        let got = tokio::time::timeout(std::time::Duration::from_secs(5), served)
            .await
            .expect("the client's connection ended")
            .expect("join");
        assert!(got.is_empty(), "the refusing root client wrote {} bytes", got.len());
    }

    /// **A root client reaches a door its directory's owner serves, and one root
    /// serves**, over real sockets: this process serves in a directory whose path
    /// holds, as that directory's owner; and, stood in as root, in one under `/tmp`.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_root_client_reaches_the_door_directorys_owner_and_root() {
        let held = held_dir();
        let endpoint = IpcEndpoint::UnixSocket(held.path().join("kotton").join("vault.sock"));
        let listener = OsListener::bind(endpoint.clone()).await.expect("bind");
        let accept = tokio::spawn(async move { listener.accept_with_peer().await });
        let mut client = OsConnection::connect_holding_door(&endpoint, another_uid()).await.expect("the owner");
        let mut accepted = accept.await.expect("join").expect("accept");
        client.write(b"hi").await.expect("write");
        let mut buf = [0u8; 2];
        accepted.connection.read(&mut buf).await.expect("read");
        assert_eq!(&buf, b"hi");

        let tmp = socket_dir();
        let endpoint = IpcEndpoint::UnixSocket(tmp.path().join("vault.sock"));
        let listener = OsListener::bind(endpoint.clone()).await.expect("bind");
        let accept = tokio::spawn(async move { listener.accept_with_peer().await });
        OsConnection::connect_holding_door(&endpoint, own_uid()).await.expect("root, with no directory read");
        accept.await.expect("join").expect("accept");
    }
}
