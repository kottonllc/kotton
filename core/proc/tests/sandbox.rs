// SPDX-License-Identifier: AGPL-3.0-or-later
// Unix-only, and not merely because the probes use Unix sockets: on a platform
// where `confine` refuses there is nothing to measure through it. On Windows
// the provider exists and `confine` cannot yet reach it, because a `Command`
// cannot carry the attribute list an AppContainer is attached by
// (`TASK-windows-cannot-confine-a-guest-so-kotton-will-not-run-one-there`,
// escalated). Until that is answered the same probes, including the Windows
// arm of the one assertion here that is Unix-shaped, are unit tests beside the
// provider in `src/provider/sandbox/windows.rs`, where the crate-private spawn
// is reachable; this file gains a Windows arm when `confine` does.
#![cfg(unix)]

//! The sandbox, measured against the kernel rather than against its own
//! builder.
//!
//! Every assertion here spawns a real process under a real profile and asks the
//! operating system what it may do. The unit tests beside the provider check
//! that the ruleset and the filter are *shaped* right; this file is the only
//! thing that can tell whether they are *enforced*, and the distinction is the
//! most expensive failure there is — an instrument that cannot perceive the
//! thing returning a confident wrong answer.
//!
//! # How a probe works
//!
//! The confined process is this test binary, re-run with
//! `KOTTON_SANDBOX_PROBE` set and a filter that selects the one `#[test]`
//! below which reads it. That test performs a single operation and exits
//! [`EXIT_ALLOWED`] or [`EXIT_REFUSED`].
//!
//! It is a binary that already exists, built by the same command that runs
//! these tests, so there is no fixture to keep in step and no chance of the
//! suite passing because the thing it meant to spawn was not built. The cost is
//! one `#[test]` that is a no-op in the parent, which is the line below that
//! returns early.

use kotton_proc::sandbox::{confine, Profile, SandboxError};
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

/// The probe did the thing.
const EXIT_ALLOWED: i32 = 0;
/// The kernel refused it.
const EXIT_REFUSED: i32 = 3;
/// The probe could not tell (a failure that was not a refusal).
const EXIT_UNCLEAR: i32 = 4;

const PROBE_VAR: &str = "KOTTON_SANDBOX_PROBE";

/// The confined half of every test in this file.
///
/// A no-op in the parent. In a child spawned by [`probe`] it is the whole
/// program: one operation, one exit code, nothing else.
#[test]
fn sandbox_probe() {
    let Ok(op) = std::env::var(PROBE_VAR) else {
        return;
    };
    let code = match run_probe(&op) {
        Ok(()) => EXIT_ALLOWED,
        Err(e) if e.kind() == ErrorKind::PermissionDenied => EXIT_REFUSED,
        Err(e) => {
            eprintln!("probe {op}: {e} ({:?})", e.kind());
            EXIT_UNCLEAR
        }
    };
    // Not a panic and not a return: libtest would report either as a test
    // outcome in a process whose whole job is its exit code.
    std::process::exit(code);
}

fn run_probe(op: &str) -> std::io::Result<()> {
    use std::net::{TcpStream, UdpSocket};
    use std::os::unix::net::UnixStream;

    match op.split_once(':') {
        Some(("read", path)) => std::fs::read(path).map(|_| ()),
        Some(("write", path)) => std::fs::write(path, b"probe"),
        // A write that does not truncate. `std::fs::write` opens with
        // `O_TRUNC`, and Landlock checks truncation as its own right, so a
        // refusal of `write` could be the truncate being refused while the
        // write itself was granted. This asks for the write right alone.
        Some(("overwrite", path)) => {
            use std::io::Write;
            std::fs::OpenOptions::new()
                .write(true)
                .open(path)?
                .write_all(b"probe")
        }
        Some(("list", path)) => std::fs::read_dir(path).map(|_| ()),
        None => match op {
            // Port 9 is discard and nothing listens on it here. The refusal
            // being looked for happens at `socket(2)`, before any address is
            // used, so what is on the far end never enters into it.
            "tcp" => TcpStream::connect("127.0.0.1:9").map(|_| ()),
            "udp" => UdpSocket::bind("127.0.0.1:0").map(|_| ()),
            "unix" => UnixStream::connect("/run/kotton-no-such-socket").map(|_| ()),
            // Allowed on purpose, and asserted so that the allowance is a
            // decision this suite would notice losing: Tokio's process and
            // signal machinery builds one of these, so a filter that refused it
            // would break the runtime of everything it confines.
            "socketpair" => UnixStream::pair().map(|_| ()),
            // `socket(2)` and nothing after it. The three probes above are
            // refused at `socket(2)` today, but each would be refused again at
            // `connect` or `bind`, so none of them can tell whether the socket
            // call itself is closed.
            #[cfg(target_os = "linux")]
            "socket" => raw::socket_alone(),
            // A socket made inside the kernel by an `io_uring` operation,
            // where no `socket(2)` is ever called.
            #[cfg(target_os = "linux")]
            "uring-socket" => raw::uring_socket(),
            other => panic!("unknown probe {other}"),
        },
        Some((other, _)) => panic!("unknown probe {other}"),
    }
}

/// Spawn this binary confined to `profile`, running `op`, and return its exit
/// code.
fn probe(profile: Profile, op: &str) -> i32 {
    let mut cmd = tokio::process::Command::new(test_binary());
    cmd.args(["--exact", "sandbox_probe", "--nocapture", "--test-threads=1"])
        .env(PROBE_VAR, op)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    confine(&mut cmd, &profile).expect("the profile is enforceable on this kernel");

    let out = runtime().block_on(async move { cmd.output().await }).expect(
        "the confined child started; a failure here is the sandbox refusing the spawn itself",
    );
    if !out.stderr.is_empty() {
        eprintln!(
            "probe {op} said: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    out.status.code().unwrap_or_else(|| {
        panic!(
            "the probe was killed by a signal rather than exiting: {:?}",
            out.status
        )
    })
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime")
}

fn test_binary() -> PathBuf {
    std::env::current_exe().expect("a test binary knows its own path")
}

/// A profile that can start this binary and reach nothing else.
fn bare() -> Profile {
    Profile::nothing("sandbox-test").executing(test_binary())
}

/// A directory this test owns, with one file in it.
fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("kotton-sandbox-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch directory");
    std::fs::write(dir.join("file"), b"contents").expect("scratch file");
    dir
}

// ── The network ──────────────────────────────────────────────────────────────

#[test]
fn a_confined_process_cannot_open_a_tcp_socket() {
    assert_eq!(probe(bare(), "tcp"), EXIT_REFUSED);
}

#[test]
fn a_confined_process_cannot_bind_a_udp_socket() {
    assert_eq!(probe(bare(), "udp"), EXIT_REFUSED);
}

#[test]
fn a_confined_process_cannot_reach_a_unix_socket() {
    assert_eq!(probe(bare(), "unix"), EXIT_REFUSED);
}

/// The one socket call that is allowed, and why it does not weaken the rest: a
/// `socketpair` is joined to itself and cannot be named, connected to, or
/// reached from outside the process.
#[test]
fn a_confined_process_may_still_make_a_pair_with_itself() {
    assert_eq!(probe(bare(), "socketpair"), EXIT_ALLOWED);
}

/// `socket(2)` itself, with no connect or bind after it to be refused instead.
///
/// Every family a confined process might want is tried, and one success is an
/// escape: the question is whether the call that makes an endpoint is closed,
/// not whether a particular address is reachable.
#[cfg(target_os = "linux")]
#[test]
fn the_socket_call_itself_is_refused() {
    assert_eq!(probe(bare(), "socket"), EXIT_REFUSED);
}

/// `io_uring` creates a socket inside the kernel, without `socket(2)`, so a
/// filter that closes the syscall does not close this. It was open until
/// 2026-09-23 (`DEC-0074`, "io_uring was a second door"): a confined process
/// made an `AF_INET` socket through a ring and sent a datagram a listener
/// received. The same operation succeeds in this process first, so what the
/// probe meets is the sandbox and not a kernel built without `io_uring`.
#[cfg(target_os = "linux")]
#[test]
fn a_socket_cannot_be_made_through_io_uring() {
    raw::uring_socket().expect(
        "io_uring can make a socket unconfined on this kernel; if it cannot (a kernel \
         without io_uring, or kernel.io_uring_disabled set), this test measures nothing here",
    );
    assert_eq!(probe(bare(), "uring-socket"), EXIT_REFUSED);
}

/// The two ways into the kernel the socket probes take that `std` does not
/// offer.
#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
mod raw {
    use std::io;
    use std::sync::atomic::{AtomicU32, Ordering};

    /// `Ok` if any family's socket was created; `PermissionDenied` only if
    /// every one was refused.
    pub fn socket_alone() -> io::Result<()> {
        let mut last = None;
        for family in [libc::AF_INET, libc::AF_INET6, libc::AF_UNIX, libc::AF_NETLINK] {
            // SAFETY: `socket` takes three integers and returns a descriptor
            // or -1; the descriptor is closed below and nothing else holds it.
            let fd = unsafe { libc::socket(family, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
            if fd >= 0 {
                // SAFETY: `fd` is ours and open.
                unsafe { libc::close(fd) };
                return Ok(());
            }
            let err = io::Error::last_os_error();
            // A family this kernel was built without says nothing either way.
            if err.raw_os_error() == Some(libc::EAFNOSUPPORT) {
                continue;
            }
            if err.kind() != io::ErrorKind::PermissionDenied {
                return Err(err);
            }
            last = Some(err);
        }
        Err(last.unwrap_or_else(|| io::Error::other("no family was supported")))
    }

    const IORING_OFF_SQ_RING: libc::off_t = 0;
    const IORING_OFF_CQ_RING: libc::off_t = 0x0800_0000;
    const IORING_OFF_SQES: libc::off_t = 0x1000_0000;
    const IORING_FEAT_SINGLE_MMAP: u32 = 1;
    const IORING_OP_SOCKET: u8 = 45;
    const IORING_ENTER_GETEVENTS: u32 = 1;

    /// `struct io_sqring_offsets` / `struct io_cqring_offsets`: the same size
    /// and the fields this reads in the same places.
    #[repr(C)]
    #[derive(Default)]
    struct RingOffsets {
        head: u32,
        tail: u32,
        ring_mask: u32,
        ring_entries: u32,
        /// `flags` on the submission ring, `overflow` on the completion one.
        _flags_or_overflow: u32,
        /// `dropped` on the submission ring, `cqes` on the completion one.
        dropped_or_cqes: u32,
        /// `array` on the submission ring, `flags` on the completion one.
        array_or_flags: u32,
        _resv1: u32,
        _user_addr: u64,
    }

    /// `struct io_uring_params`.
    #[repr(C)]
    #[derive(Default)]
    struct Params {
        sq_entries: u32,
        cq_entries: u32,
        flags: u32,
        sq_thread_cpu: u32,
        sq_thread_idle: u32,
        features: u32,
        wq_fd: u32,
        resv: [u32; 3],
        sq_off: RingOffsets,
        cq_off: RingOffsets,
    }

    /// `struct io_uring_sqe`, 64 bytes, with only the fields
    /// `IORING_OP_SOCKET` reads named.
    #[repr(C)]
    struct Sqe {
        opcode: u8,
        flags: u8,
        ioprio: u16,
        /// The address family.
        fd: i32,
        /// The socket type.
        off: u64,
        addr: u64,
        /// The protocol.
        len: u32,
        op_flags: u32,
        user_data: u64,
        rest: [u64; 3],
    }

    /// `struct io_uring_cqe`.
    #[repr(C)]
    struct Cqe {
        _user_data: u64,
        res: i32,
        _flags: u32,
    }

    struct Map(*mut libc::c_void, usize);

    impl Map {
        fn new(ring: i32, len: usize, offset: libc::off_t) -> io::Result<Self> {
            // SAFETY: a fresh shared mapping of the ring's own memory; the
            // kernel checks `offset` and `len` against the ring.
            let p = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    len,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_SHARED | libc::MAP_POPULATE,
                    ring,
                    offset,
                )
            };
            if p == libc::MAP_FAILED {
                return Err(io::Error::last_os_error());
            }
            Ok(Self(p, len))
        }

        /// SAFETY: `off` plus the size of `T` lies inside the mapping, which
        /// the ring's own offsets guarantee for every place this is called.
        unsafe fn at<T>(&self, off: u32) -> *mut T {
            unsafe { self.0.cast::<u8>().add(off as usize).cast::<T>() }
        }
    }

    impl Drop for Map {
        fn drop(&mut self) {
            // SAFETY: mapped in `new` and unmapped once.
            unsafe { libc::munmap(self.0, self.1) };
        }
    }

    /// Make an `AF_INET` datagram socket with `IORING_OP_SOCKET` and close
    /// it: `Ok` if the kernel made one.
    pub fn uring_socket() -> io::Result<()> {
        let mut p = Params::default();
        // SAFETY: `p` is a zeroed `io_uring_params` the kernel fills in.
        let fd = unsafe { libc::syscall(libc::SYS_io_uring_setup, 1u32, &mut p as *mut Params) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: the kernel returned a fresh descriptor and nothing else owns it.
        let ring = unsafe { <std::os::fd::OwnedFd as std::os::fd::FromRawFd>::from_raw_fd(fd as i32) };
        let ring_fd = std::os::fd::AsRawFd::as_raw_fd(&ring);

        let sq_len = p.sq_off.array_or_flags as usize + p.sq_entries as usize * 4;
        let cq_len = p.cq_off.dropped_or_cqes as usize
            + p.cq_entries as usize * std::mem::size_of::<Cqe>();
        let single = p.features & IORING_FEAT_SINGLE_MMAP != 0;
        let sq = Map::new(ring_fd, if single { sq_len.max(cq_len) } else { sq_len }, IORING_OFF_SQ_RING)?;
        let cq_own = if single { None } else { Some(Map::new(ring_fd, cq_len, IORING_OFF_CQ_RING)?) };
        let cq = cq_own.as_ref().unwrap_or(&sq);
        let sqes = Map::new(
            ring_fd,
            p.sq_entries as usize * std::mem::size_of::<Sqe>(),
            IORING_OFF_SQES,
        )?;

        // SAFETY: every offset below is one the kernel reported for this ring.
        let res = unsafe {
            let sqe = Sqe {
                opcode: IORING_OP_SOCKET,
                flags: 0,
                ioprio: 0,
                fd: libc::AF_INET,
                off: libc::SOCK_DGRAM as u64,
                addr: 0,
                len: 0,
                op_flags: 0,
                user_data: 0,
                rest: [0; 3],
            };
            let tail = &*sq.at::<AtomicU32>(p.sq_off.tail);
            let mask = *sq.at::<u32>(p.sq_off.ring_mask);
            let t = tail.load(Ordering::Acquire);
            let slot = t & mask;
            sqes.at::<Sqe>(slot * std::mem::size_of::<Sqe>() as u32).write(sqe);
            sq.at::<u32>(p.sq_off.array_or_flags + slot * 4).write(slot);
            tail.store(t.wrapping_add(1), Ordering::Release);

            let entered = libc::syscall(
                libc::SYS_io_uring_enter,
                ring_fd,
                1u32,
                1u32,
                IORING_ENTER_GETEVENTS,
                std::ptr::null::<libc::c_void>(),
                0usize,
            );
            if entered < 0 {
                return Err(io::Error::last_os_error());
            }
            let head = &*cq.at::<AtomicU32>(p.cq_off.head);
            let cmask = *cq.at::<u32>(p.cq_off.ring_mask);
            let h = head.load(Ordering::Acquire);
            let cqe = cq
                .at::<Cqe>(p.cq_off.dropped_or_cqes + (h & cmask) * std::mem::size_of::<Cqe>() as u32)
                .read();
            head.store(h.wrapping_add(1), Ordering::Release);
            cqe.res
        };
        if res < 0 {
            return Err(io::Error::from_raw_os_error(-res));
        }
        // SAFETY: the completion is a descriptor the kernel just made for us.
        unsafe { libc::close(res) };
        Ok(())
    }
}

// ── The filesystem ───────────────────────────────────────────────────────────

#[test]
fn a_path_outside_every_grant_is_unreadable() {
    let dir = scratch("ungranted");
    let file = dir.join("file");
    // The same file is readable to this process, so what the probe meets is the
    // sandbox and not a permission bit.
    assert!(std::fs::read(&file).is_ok());
    assert_eq!(probe(bare(), &format!("read:{}", file.display())), EXIT_REFUSED);
}

#[test]
fn a_granted_path_is_readable_and_still_not_writable() {
    let dir = scratch("read-grant");
    let file = dir.join("file");
    let profile = || bare().reading(&dir);
    assert_eq!(
        probe(profile(), &format!("read:{}", file.display())),
        EXIT_ALLOWED
    );
    assert_eq!(
        probe(profile(), &format!("write:{}", file.display())),
        EXIT_REFUSED
    );
    // The truncating write above is refused at the truncate if nowhere else,
    // so on its own it cannot tell a read grant from one that also writes.
    // This one asks for the write right and nothing more.
    assert_eq!(
        probe(profile(), &format!("overwrite:{}", file.display())),
        EXIT_REFUSED
    );
}

#[test]
fn a_write_grant_reaches_beneath_itself_and_no_further() {
    let granted = scratch("write-grant");
    let neighbour = scratch("write-neighbour");
    let profile = || bare().writing(&granted);
    assert_eq!(
        probe(profile(), &format!("write:{}", granted.join("new").display())),
        EXIT_ALLOWED
    );
    assert_eq!(
        probe(
            profile(),
            &format!("write:{}", neighbour.join("new").display())
        ),
        EXIT_REFUSED
    );
    // A sibling directory is not reachable by walking up out of the grant
    // either: Landlock names an inode, and `..` does not escape it.
    assert_eq!(
        probe(
            profile(),
            &format!(
                "read:{}",
                granted
                    .join("..")
                    .join(neighbour.file_name().expect("a named directory"))
                    .join("file")
                    .display()
            )
        ),
        EXIT_REFUSED
    );
}

/// `DEC-0074` §3 splits the inference runtime into a half that may hold the
/// graphics device and a half that may not. This is the profile being able to
/// say which — against `/dev/null`, because a test may not assume a machine has
/// a GPU, and because what is being measured is that the grant is *specific*.
#[test]
fn a_device_grant_reaches_that_device_and_not_another() {
    let profile = || bare().device("/dev/null");
    assert_eq!(probe(profile(), "write:/dev/null"), EXIT_ALLOWED);
    assert_eq!(probe(profile(), "read:/dev/zero"), EXIT_REFUSED);
    // And a half that was not given one reaches neither.
    assert_eq!(probe(bare(), "write:/dev/null"), EXIT_REFUSED);
}

// ── The refusals that happen before a spawn ──────────────────────────────────

/// With nothing granted, the `execve` the sandbox is applied in front of is
/// itself the first thing denied. This is the test that would fail if the
/// confinement were silently not applied at all — every other assertion here
/// could pass against a kernel that ignored the ruleset, and this one could
/// not.
///
/// **On Windows** this property does not hold, and is not claimed:
/// `CreateProcessW` opens the image with the parent's token, so a child with no
/// grant is created (#65). What the kernel enforces is the child's token once it
/// runs, and the Windows test that fails if the container is silently not
/// attached is
/// `provider::sandbox::windows::tests::a_child_granted_nothing_can_read_neither_its_own_image_nor_a_file_beside_it`.
#[test]
fn a_profile_that_grants_nothing_cannot_even_start_the_program() {
    let mut cmd = tokio::process::Command::new(test_binary());
    cmd.env(PROBE_VAR, "socketpair")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    confine(&mut cmd, &Profile::nothing("no-grants")).expect("enforceable");
    let err = runtime()
        .block_on(async move { cmd.output().await })
        .expect_err("a program with no grant on its own image cannot be executed");
    assert_eq!(err.kind(), ErrorKind::PermissionDenied, "{err}");
}

#[test]
fn a_grant_on_a_path_that_does_not_exist_is_refused_before_the_spawn() {
    let mut cmd = tokio::process::Command::new(test_binary());
    let missing = Path::new("/nonexistent/kotton/sandbox/grant");
    let err = confine(&mut cmd, &bare().reading(missing))
        .expect_err("a grant naming nothing is the caller's bug and says so");
    match err {
        SandboxError::NoSuchGrant { path, purpose } => {
            assert_eq!(path, missing);
            assert_eq!(purpose, "sandbox-test");
        }
        other => panic!("expected NoSuchGrant, got {other}"),
    }
}

/// The profile carries what the caller wrote and nothing it did not.
#[test]
fn a_profile_is_the_lines_at_its_call_site() {
    let p = Profile::nothing("reader").reading("/tmp").writing("/var/tmp");
    assert_eq!(p.purpose(), "reader");
    assert_eq!(p.grants().len(), 2);
    assert_eq!(p.grants()[0].path, Path::new("/tmp"));
    assert_eq!(p.grants()[1].path, Path::new("/var/tmp"));
}
